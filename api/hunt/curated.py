"""Threat Curated Rules (Admin > Threat Curated Rules): run first, for free; the AI is paid only for what they don't
already explain, and every high-fidelity finding it makes becomes a new rule so the same finding never costs twice.

A rule is generic so it can be reused anywhere: never a host, user, address or account, only what the pattern is.
  alert   matches the alerts CTEM keeps from every tool: MITRE techniques or tactics, title words, the source,
          and optionally "on N or more hosts" or "N or more alerts" in the hunt's time range
  splunk  a read-only Splunk search with no host or user in it (the same guard as every hunt search)
Nothing in a rule is ever run as code or SQL."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy import select

log = logging.getLogger("open-ctem.hunt.curated")
SEVERITIES = ("critical", "high", "medium", "low")
SOURCES = ("crowdstrike", "sentinelone", "msdefender", "cortex_xdr", "guardicore", "fortinet", "paloalto_ngfw", "splunk", "grip")
_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC = re.compile(r"^TA\d{4}$")
_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()/+:-]{1,58}[A-Za-z0-9)]$")
_PERSONAL = re.compile(r"[\\@]|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{12,}\b", re.I)   # DOMAIN\user, mail, IPs, ids
DAYS = {"24h": 1, "7d": 7, "30d": 30, "all": 3650}
MAX_ISSUES = 20


def _clean_list(v, pattern, n, upper=False) -> list[str]:
    out = []
    for x in (v if isinstance(v, list) else [])[:n * 2]:
        x = str(x).strip().upper() if upper else str(x).strip()
        if x and pattern.match(x) and x not in out:
            out.append(x)
    return out[:n]


def validate(kind: str, match: dict, names: set[str] | None = None) -> dict:
    """The rule's match, cleaned to the allow-list and kept generic; raises ValueError if nothing reusable is left."""
    names = names or set()

    def generic(word: str) -> bool:
        w = word.lower()
        if _PERSONAL.search(word) or w in names:
            return False
        try:
            ipaddress.ip_address(word)
            return False
        except ValueError:
            return True
    if not isinstance(match, dict):
        raise ValueError("a rule needs a match")
    if kind == "alert":
        words = lambda k, n: [w for w in _clean_list(match.get(k), _WORD, n) if generic(w)]   # noqa: E731
        out = {"technique_ids": _clean_list(match.get("technique_ids"), _TECH, 10, upper=True),
               "tactic_ids": _clean_list(match.get("tactic_ids"), _TACTIC, 5, upper=True),
               "title_any": words("title_any", 10), "title_all": words("title_all", 5),
               "sources": [s for s in _clean_list(match.get("sources"), re.compile(r"^[a-z_]{2,32}$"), 5) if s in SOURCES],
               "min_hosts": min(max(int(match.get("min_hosts") or 1), 1), 1000),
               "min_alerts": min(max(int(match.get("min_alerts") or 1), 1), 10000)}
        if not (out["technique_ids"] or out["title_any"] or out["title_all"]):
            raise ValueError("an alert rule needs a MITRE technique or title words, not just a source or tactic")
        return out
    if kind == "splunk":
        from api.hunt.spl_guard import vet_spl
        spl = str(match.get("spl") or "").strip()
        if not spl or _PERSONAL.search(spl) or any(n and re.search(rf"\b{re.escape(n)}\b", spl, re.I) for n in names):
            raise ValueError("a Splunk rule must be generic: no host, user, account or address in it")
        vet_spl(spl)   # read-only, bounded, or it raises
        return {"spl": spl[:2000], "min_rows": min(max(int(match.get("min_rows") or 1), 1), 100000)}
    raise ValueError("a rule is an alert pattern or a Splunk search")


def fingerprint(kind: str, match: dict) -> str:
    """Same pattern, same rule: order and case don't make a new one."""
    norm = {k: (sorted(x.lower() for x in v) if isinstance(v, list) else v) for k, v in match.items()}
    return hashlib.sha256(json.dumps([kind, norm], sort_keys=True).encode()).hexdigest()


def alert_matches(m: dict, a: dict) -> bool:
    title = f"{a.get('title') or ''} {a.get('technique') or ''}".lower()
    if m["sources"] and (a.get("source") or "") not in m["sources"]:
        return False
    if m["tactic_ids"] and (a.get("tactic_id") or "") not in m["tactic_ids"]:
        return False
    if m["technique_ids"] and not any((a.get("technique_id") or "").upper().startswith(t) for t in m["technique_ids"]):
        return False
    if m["title_any"] and not any(w.lower() in title for w in m["title_any"]):
        return False
    return all(w.lower() in title for w in m["title_all"])


async def known_names(db) -> set[str]:
    """Hosts and people CTEM knows, so a learned rule can't carry one (that would make it about one machine)."""
    from api.models.device import Device
    from api.models.user import User
    hosts = {str(h).lower() for (h,) in (await db.execute(select(Device.host_key).where(Device.host_key.is_not(None)))).all()}
    users = {str(u).lower() for (u,) in (await db.execute(select(User.username))).all()}
    return {n for n in hosts | users if len(n) >= 3}


async def _who_where(db, hits: list[dict]) -> None:
    """Each hit's user, where it came from and what it targeted, from its encrypted detail (the first 50 only)."""
    from api.core.threat_graph import origin
    from api.hunt.alert_detail import summarize
    from api.routes.threat import _detail
    for h in hits[:50]:
        if not h.get("has_detail"):
            continue
        d = await _detail(db, h["id"].partition("#")[0])
        u = d.get("user") or {}
        src = origin(d)
        h["user"] = f"{u['domain']}\\{u['name']}" if u.get("domain") and u.get("name") else u.get("name")
        h["from_ips"], h["from_hosts"], h["accounts"], h["targets"] = src["ips"], src["hosts"], src["accounts"], src["targets"]
        h.update({k: v for k, v in summarize(d).items() if k != "user"})   # process, command line, parent, file, hash


def _line(h: dict) -> str:
    bits = [h.get("title") or ""]
    if h.get("process"):
        proc = h["process"].replace("\\", "/").rsplit("/", 1)[-1]
        bits.append(f"by {proc}" + (f" (started by {h['parent']})" if h.get("parent") else ""))
    if h.get("file"):
        bits.append(f"on {h['file']}")
    if h.get("from_ips") or h.get("from_hosts"):
        bits.append("from " + ", ".join([*h.get("from_ips", []), *h.get("from_hosts", [])][:4]))
    if h.get("targets"):
        bits.append("against " + ", ".join(h["targets"][:4]))
    if h.get("user"):
        bits.append(f"as {h['user']}")
    return " ".join(bits)[:500]


def _issue(rule, hits: list[dict], lookup_no: int) -> dict:
    hosts = sorted({h["hostname"] for h in hits if h.get("hostname")} | {x for h in hits for x in h.get("from_hosts", [])})
    users = sorted({x for h in hits for x in [h.get("user"), *h.get("accounts", []), *h.get("targets", [])] if x})
    ips = sorted({x for h in hits for x in h.get("from_ips", [])})
    when = sorted(hits, key=lambda h: h.get("detected_at") or "")
    return {
        "title": rule.name, "severity": rule.severity, "confidence": "high", "from_rule": str(rule.id),
        "what_happened": (f"{len(hits)} alert{'s' if len(hits) != 1 else ''} on {len(hosts)} host{'s' if len(hosts) != 1 else ''} "
                          f"matched the curated rule \"{rule.name}\".")[:1500],
        "why_it_matters": (rule.description or "")[:600],
        "timeline": [{"time": str(h.get("detected_at") or "")[:16].replace("T", " "), "source": h.get("source") or "",
                      "what": _line(h), "lookup": lookup_no} for h in when[:12]],
        "involved": {"hosts": hosts[:15], "users": users[:15], "ips": ips[:15]},
        "what_to_do": [str(x)[:300] for x in (rule.what_to_do or [])][:8],
        "attack": rule.attack or [], "lookups": [lookup_no],
    }


async def run(db, splunk, time_range: str, first_lookup: int) -> tuple[list[dict], list[dict], set[str]]:
    """Every enabled rule over the time range. Returns (issues, their evidence as lookups, alert ids they explain)."""
    from api.hunt import curated_pack
    from api.models.threat_rule import ThreatRule
    from api.routes.threat import _alerts
    await curated_pack.sync(db)
    rules = (await db.execute(select(ThreatRule).where(ThreatRule.enabled.is_(True)))).scalars().all()
    if not rules:
        return [], [], set()
    since_at = datetime.now(timezone.utc) - timedelta(days=DAYS.get(time_range, 7))
    since = since_at.isoformat()
    every = await _alerts(db) if any(r.kind == "alert" for r in rules) else []   # the history context weighs hits against
    alerts = [a for a in every if (a.get("detected_at") or "") >= since]
    if alerts:   # accepted alerts (the allow list) never raise a finding
        from api.core.alert_allow import accepted
        gone = await accepted(db, alerts, count=True)
        alerts = [a for a in alerts if a["id"] not in gone]
    issues, lookups, explained, now = [], [], set(), datetime.now(timezone.utc)
    for rule in rules:
        try:
            if rule.kind == "alert":
                hits = [a for a in alerts if alert_matches(rule.match, a)]
                hosts = {a.get("hostname") for a in hits if a.get("hostname")}
                if not hits or len(hits) < rule.match["min_alerts"] or len(hosts) < rule.match["min_hosts"]:
                    continue
                hits = [dict(a) for a in hits]
                await _who_where(db, hits)
                from api.hunt.alert_detail import console_links
                links = await console_links(db, hits[:100])
                rows = [{"detected": a.get("detected_at"), "host": a.get("hostname"), "user": a.get("user"),
                         "from": ", ".join([*a.get("from_ips", []), *a.get("from_hosts", [])][:6]) or None,
                         "targeted": ", ".join(a.get("targets", [])[:6]) or None, "source": a.get("source"),
                         "alert": a.get("title"), "process": a.get("process"), "command_line": a.get("command_line"),
                         "parent": a.get("parent"), "file": a.get("file"), "sha256": a.get("sha256"), "technique": a.get("technique_id"),
                         "alert_page": f"/threat/alert?id={quote(a['id'], safe='')}", "crowdstrike": links.get(a["id"])}
                        for a in hits[:100]]
                explained |= {a["id"] for a in hits}
            elif rule.kind == "splunk" and splunk is not None:
                from api.hunt.spl_guard import TIME_RANGES, vet_spl
                found = await splunk.run_search(vet_spl(rule.match["spl"]), earliest=TIME_RANGES.get(time_range, "-7d"))
                if len(found) < rule.match["min_rows"]:
                    continue
                hits = [{"hostname": r.get("host") or r.get("ComputerName") or r.get("dest"), "detected_at": r.get("_time"),
                         "source": "splunk", "title": rule.name} for r in found]
                rows = [{k: v for k, v in r.items() if not k.startswith("_") or k == "_time"} for r in found[:100]]
            else:
                continue
        except Exception:
            log.warning("curated rule %s failed", rule.id, exc_info=True)
            continue
        n = first_lookup + len(lookups)
        cols = [c for c in (rows[0].keys() if rows else []) if any(r.get(c) not in (None, "") for r in rows)][:18]
        lookups.append({"source": "ctem", "source_label": "Curated rule", "title": f"Curated rule: {rule.name}",
                        "why": "A Threat Curated Rule; no AI tokens spent", "columns": cols,
                        "rows": [{c: r.get(c) for c in cols} for r in rows], "count": len(rows), "table": "curated", "filters": {}})
        issue = _issue(rule, hits, n)
        if rule.kind == "alert":   # how this time looks against what CTEM already knows (api/hunt/context.py)
            from api.hunt.context import explain, weigh
            ctx = weigh(hits, every, since_at)
            issue["confidence"], issue["context"] = ctx["confidence"], ctx["notes"]
            issue["what_happened"] = (issue["what_happened"] + explain(ctx))[:1500]
        issues.append(issue)
        rule.hits, rule.last_hit_at = (rule.hits or 0) + 1, now
        if len(issues) >= MAX_ISSUES:
            break
    await db.commit()
    return issues, lookups, explained


async def learn(db, issues: list[dict], question: str) -> int:
    """Each high-fidelity AI finding that came with a generic rule becomes one (or freshens the one it matches)."""
    from api.hunt.watch import worth_showing
    from api.models.threat_rule import ThreatRule
    names, n = None, 0
    for i in issues:
        draft = i.pop("rule_draft", None)
        if not isinstance(draft, dict) or i.get("from_rule") or not worth_showing(i):
            continue
        kind = str(draft.get("kind") or "alert")
        names = names if names is not None else await known_names(db)
        # Never the hosts, people or addresses of the very finding it came from (they may not be in CTEM yet)
        inv = i.get("involved") or {}
        own = {str(x).lower() for k in ("hosts", "users", "ips") for x in inv.get(k) or []}
        try:
            match = validate(kind, draft.get("match") or {}, names | own)
        except (ValueError, TypeError):
            continue
        fp = fingerprint(kind, match)
        row = (await db.execute(select(ThreatRule).where(ThreatRule.fingerprint == fp))).scalar_one_or_none()
        if row is not None:
            continue   # already curated: nothing new to learn
        name = str(draft.get("name") or i["title"]).strip()[:120]
        if any(w and w in name.lower() for w in names if len(w) >= 5):
            name = i["title"][:120] if not any(w in i["title"].lower() for w in names if len(w) >= 5) else "Learned detection"
        db.add(ThreatRule(name=name, kind=kind, match=match, fingerprint=fp, severity=i["severity"],
                          description=(str(draft.get("why") or i.get("why_it_matters") or ""))[:600] or None,
                          what_to_do=[str(x)[:300] for x in (i.get("what_to_do") or [])][:8],
                          attack=[{"id": a["id"], "name": a.get("name", "")} for a in i.get("attack") or []][:6],
                          status="learned", learned_from=question[:500], created_by="ai"))
        n += 1
    if n:
        await db.commit()
        log.info("curated rules: learned %d new rule%s", n, "" if n == 1 else "s")
    return n
