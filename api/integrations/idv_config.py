"""Checks on the Persona and Twilio integration settings before they are stored (a saved secret arrives as
__REDACTED__ on an edit and is left alone)."""
from __future__ import annotations

import re

_KEPT = "__REDACTED__"
_PERSONA_KEY = re.compile(r"^persona_(production|sandbox)_[A-Za-z0-9\-]{20,80}$")
_TEMPLATE = re.compile(r"^(itmpl|tmpl)_[A-Za-z0-9]{8,40}$")
_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")


def _num(config: dict, key: str, lo: int, hi: int, what: str) -> None:
    v = config.get(key)
    if v in (None, ""):
        return
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be a whole number") from None
    if not lo <= n <= hi:
        raise ValueError(f"{what} must be from {lo} to {hi}")


_ORIGIN = re.compile(r"^https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def desk_origins(config: dict, strict: bool = False) -> list[str]:
    """The ServiceNow (or other service desk) origins allowed to frame the caller verification panel: exact
    https://host, no path, port or wildcard."""
    out = []
    for o in str(config.get("desk_frame_origins") or "").replace("\n", ",").split(","):
        o = o.strip().rstrip("/").lower()
        if not o:
            continue
        if not _ORIGIN.match(o):
            if strict:
                raise ValueError(f"Service desk origins are exact https addresses like https://acme.service-now.com (not {o[:60]!r})")
            continue
        out.append(o)
    return out[:10]


def desk_ips(config: dict, strict: bool = False) -> list[str]:
    """The address ranges analysts' browsers must come from to use the panel (IPs or CIDRs)."""
    import ipaddress
    out = []
    for e in str(config.get("desk_client_ips") or "").replace("\n", ",").split(","):
        e = e.strip()
        if not e:
            continue
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            if strict:
                raise ValueError(f"Analyst address ranges are IPs or CIDRs like 203.0.113.0/24 (not {e[:40]!r})") from None
            continue
        if net.prefixlen == 0:
            if strict:
                raise ValueError("An analyst address range can't be the whole internet")
            continue
        out.append(str(net))
    return out[:50]


def check(vendor: str, config: dict) -> None:
    if config.get("base_url"):
        raise ValueError("This integration doesn't take a base URL")
    if vendor == "persona":
        for key in ("api_key", "action_api_key"):
            v = config.get(key)
            if v not in (None, "", _KEPT) and not _PERSONA_KEY.match(str(v)):
                raise ValueError("A Persona API key looks like persona_production_...")
        for key in ("template_id", "selfie_template_id"):
            t = config.get(key)
            if t not in (None, "") and not _TEMPLATE.match(str(t)):
                raise ValueError("An inquiry template id looks like itmpl_...")
        for t in str(config.get("badge_templates") or "").split(","):
            if t.strip() and not _TEMPLATE.match(t.strip()):
                raise ValueError("Badge templates are itmpl_... ids, comma separated")
        _num(config, "detail_budget", 0, 5000, "Device lookups per sync")
        _num(config, "max_pages", 1, 500, "Pages per sync")
        return
    if not re.fullmatch(r"AC[0-9a-f]{32}", str(config.get("account_sid") or "")):
        raise ValueError("The Account SID looks like AC followed by 32 letters and digits")
    k = config.get("api_key_sid")
    if k != _KEPT and not re.fullmatch(r"SK[0-9a-f]{32}", str(k or "")):
        raise ValueError("The API key SID looks like SK followed by 32 letters and digits")
    if isinstance(config.get("from_number"), str):   # +1 (555) 010-0100 is stored as +15550100100
        config["from_number"] = re.sub(r"[\s\-.()]", "", config["from_number"])
    if not _E164.match(str(config.get("from_number") or "")):
        raise ValueError("The sending number goes in international form, like +15550100100")
