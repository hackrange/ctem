"""Risk-based finding score: how likely a flaw is to be exploited, whether an attacker can reach it on this host,
and what it would cost, combined as a weighted geometric mean so a weak dimension isn't averaged away (a KEV flaw
nobody can reach stays low; a reachable, likely one rises). Protections in place (the EDR and what its policy
blocks, days offline, privileged credentials) then scale it, as in the classic model.

Defaults were set from a large real deployment: reachability evidence existed for well under 1% of findings, so the
ladder infers it from the CVSS attack vector, whether a service is listening, the host's
internet exposure and its role, instead of treating "unknown" as half. Admins tune the weights and the ladder in
Admin > Risk model, and Reset brings these back."""
from __future__ import annotations

import json
import math
import time

KEY = "scoring.risk_model"
DEFAULTS: dict = {
    "enabled": True,
    "weights": {"likelihood": 0.45, "reachability": 0.35, "impact": 0.20},
    "likelihood": {"kev": 1.0, "pentest_proved": 1.0, "threat_actors": 0.8, "epss_full": 0.2, "epss_curve": 1.0,
                   "no_epss_cvss": 0.15},
    "reachability": {"pentest_proved": 1.0, "internet_listening": 1.0, "listening": 0.7, "client_workstation": 0.6,
                     "client_server": 0.3, "adjacent": 0.3, "local": 0.15, "physical": 0.05, "unknown": 0.4,
                     "internet_unknown": 0.7,
                     "not_reachable": 0.02},
    "impact": {"severity": 0.6, "criticality": 0.4},
}
LIMITS = {"weights": (0.0, 1.0), "likelihood": (0.0, 1.0), "reachability": (0.0, 1.0), "impact": (0.0, 1.0)}
# In a large real deployment nearly every open finding had EPSS under 10%; the curve below was set from that
_cache: dict = {"at": 0.0, "cfg": None}


def merged(raw: dict | None) -> dict:
    """The stored settings over the defaults, each value clamped to its range; unknown keys are dropped."""
    cfg = json.loads(json.dumps(DEFAULTS))
    raw = raw if isinstance(raw, dict) else {}
    if isinstance(raw.get("enabled"), bool):
        cfg["enabled"] = raw["enabled"]
    for group, (lo, hi) in LIMITS.items():
        for k, v in (raw.get(group) or {}).items() if isinstance(raw.get(group), dict) else []:
            if k in cfg[group] and isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v):
                cfg[group][k] = round(min(hi, max(lo, float(v))), 4)
    if sum(cfg["weights"].values()) <= 0:
        cfg["weights"] = dict(DEFAULTS["weights"])
    if sum(cfg["impact"].values()) <= 0:
        cfg["impact"] = dict(DEFAULTS["impact"])
    return cfg


async def load(db) -> dict:
    """The active settings. The row is read each time (one small query) and parsed only when it changed, so a
    rescore queued right after an admin saves uses the new model, in whichever process runs it."""
    from sqlalchemy import select

    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting.value).where(AppSetting.key == KEY))).scalar_one_or_none()
    if _cache["cfg"] is not None and _cache.get("raw") == row:
        return _cache["cfg"]
    try:
        raw = json.loads(row) if row else None
    except ValueError:
        raw = None
    _cache.update(at=time.monotonic(), cfg=merged(raw), raw=row)
    return _cache["cfg"]


def forget() -> None:
    _cache.update(at=0.0, cfg=None, raw=None)


def current() -> dict:
    return _cache["cfg"] or merged(None)


def likelihood(cfg: dict, cvss: float, epss: float, kev: bool, ctx) -> tuple[float, str]:
    c = cfg["likelihood"]
    # EPSS at epss_full or above counts as certain; below it, the curve keeps a 0.2% EPSS low (most of the fleet's
    # findings) while 10% already counts for a lot
    full = max(c["epss_full"], 0.01)
    # No EPSS yet (FIRST never scores a CVE exactly 0) gets a cautious prior from CVSS. A measured low EPSS ranks
    # below that prior on purpose: it is evidence, the prior is a guess.
    options = [(min(1.0, epss / full) ** c["epss_curve"] if epss > 0 else 0.0, f"EPSS {epss * 100:.1f}%")]
    if not epss:
        options.append(((cvss / 10.0) * c["no_epss_cvss"], f"no EPSS yet; CVSS {cvss:.1f}"))
    if kev:
        options.append((c["kev"], "known exploited (KEV)"))
    if ctx.nodezero_confirmed_exploitable:
        options.append((c["pentest_proved"], "a pentest exploited it here"))
    if ctx.threat_actors:
        options.append((c["threat_actors"], "adversaries are using it"))
    return max(options, key=lambda o: o[0])


def reachability(cfg: dict, ctx, device_type: str, is_reachable: bool | None = None) -> tuple[float, str]:
    """The evidence ladder: the strongest fact about whether an attacker can get to this flaw on this host.
    A flaw the scanner saw on a live service is reachable whatever its CVSS attack vector says (NVD's vector is
    often wrong for old network flaws such as guessable SNMP communities), but a local or physical vector doesn't
    get the internet-facing rung. Host firewall and segmentation discounts apply after every rung."""
    from api.scoring.compensating import _cloud_reach
    r = cfg["reachability"]
    av = (ctx.attack_vector or "").lower()
    if ctx.nodezero_confirmed_exploitable:
        value, why = r["pentest_proved"], "a pentest reached and exploited it"
    elif ctx.port_closed or ctx.nodezero_confirmed_not_exploitable:
        value, why = r["not_reachable"], ctx.port_closed or "a pentest found it not exploitable"
    elif ctx.exposure == "listening":
        value, why = ((r["internet_listening"], "listening service on an internet-facing host")
                      if ctx.is_internet_exposed and av not in ("local", "physical") else (r["listening"], f"listening service {ctx.ports or ''}".strip()))
        if ctx.ports and ctx.cloud_ports is not None:
            f, cwhy = _cloud_reach(ctx.ports, ctx.cloud_ports)
            value, why = value * max(f, 0.0), cwhy or why
    elif av == "physical":
        value, why = r["physical"], "needs physical access"
    elif av == "local":
        value, why = r["local"], "needs local access first"
    elif av == "adjacent":
        value, why = r["adjacent"], "needs the same network segment"
    elif av == "network" and ctx.exposure == "local" and device_type in ("workstation", "server"):   # not appliances
        value, why = ((r["client_workstation"], "client-side: reached through what a person opens or browses")
                      if device_type == "workstation" else (r["client_server"], "client-side, on a server"))
    elif ctx.is_internet_exposed and av in ("network", ""):
        value, why = r["internet_unknown"], "internet-facing host; no evidence which service the flaw is on"
    else:
        value, why = r["unknown"], "no reachability evidence"
    if is_reachable is True and value < r["listening"] and not ctx.port_closed:
        value, why = r["listening"], "a source reports it reachable"   # a scanner's or code review's word
    if ctx.host_firewall and ctx.exposure == "listening":
        value *= ctx.host_firewall[0]
        why += f"; {ctx.host_firewall[1]}"
    if ctx.network_segmentation_blocks:
        value *= 0.6
        why += "; network segmentation blocks the path"
    return min(1.0, value), why


def impact(cfg: dict, cvss: float, criticality: float) -> tuple[float, str]:
    i = cfg["impact"]
    total = i["severity"] + i["criticality"]
    value = (i["severity"] * cvss / 10.0 + i["criticality"] * criticality) / total
    return value, f"CVSS {cvss:.1f}, asset criticality {criticality:.2f}"


def score(cvss: float, epss: float, kev: bool, criticality: float, ctx, device_type: str,
          cfg: dict | None = None, is_reachable: bool | None = None) -> tuple[float, list[str]]:
    """0-100 and the reasons: likelihood x reachability x impact, each after the protections that bear on it."""
    from api.scoring.compensating import protections
    cfg = cfg or current()
    reach = reachability(cfg, ctx, device_type, is_reachable)
    lik_f, imp_f, more = protections(ctx)
    lik, imp = likelihood(cfg, cvss, epss, kev, ctx), impact(cfg, cvss, criticality)
    parts = {"likelihood": (min(1.0, lik[0] * lik_f), lik[1]), "reachability": reach,
             "impact": (min(1.0, imp[0] * imp_f), imp[1])}
    w = cfg["weights"]
    total = sum(w.values())
    log = sum(w[k] * math.log(max(parts[k][0], 0.01)) for k in parts) / total
    value = 100.0 * math.exp(log)
    reasons = [f"{k.capitalize()} {parts[k][0] * 100:.1f}%: {parts[k][1]}" for k in ("likelihood", "reachability", "impact")]
    return round(max(0.0, min(100.0, value)), 1), reasons + more
