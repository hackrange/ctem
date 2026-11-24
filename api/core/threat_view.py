"""One shape for threat alerts, whichever EDR, SIEM or firewall they came from."""
from __future__ import annotations

import re
from datetime import datetime

# Short codes like the device Sources column; anything unknown shows uppercased
SOURCE_CODES = {"crowdstrike": "CS", "rapid7": "R7", "rapid7_insightvm": "R7", "rapid7_idr": "R7", "splunk": "SPL",
                "sentinelone": "S1", "msdefender": "MDE", "cortex_xdr": "XDR", "guardicore": "GC",
                "fortinet": "FGT", "paloalto_ngfw": "PAN"}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "info": 1}
SORTS = ("severity", "detected_at", "title", "source", "hostname", "status", "technique_id")

_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC = re.compile(r"^TA\d{4}$")
_LINK = re.compile(r"^https://falcon(?:\.[a-z0-9-]+)*\.crowdstrike\.com/[^\s\"'<>]*$")


def _s(v, cap: int = 300) -> str | None:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        v = str(v)
    return v.strip()[:cap] or None if isinstance(v, str) else None


def _technique(item: dict) -> str | None:
    """First real ATT&CK technique id (T1204, T1059.001) in whatever field the connector used."""
    ttps = item.get("mitre_ttps") if isinstance(item.get("mitre_ttps"), list) else []
    for v in (item.get("technique_id"), item.get("mitre_technique_id"), item.get("mitre_technique"), *ttps):
        if isinstance(v, dict):
            v = v.get("id")
        v = (_s(v, 16) or "").upper()
        if _TECH.match(v):
            return v
    return None


def _severity(v) -> str | None:
    v = (_s(v, 32) or "").lower()
    if v.isdigit():  # CrowdStrike also sends 0-100
        n = int(v)
        v = "critical" if n >= 80 else "high" if n >= 60 else "medium" if n >= 40 else "low" if n >= 20 else "informational"
    return v if v in SEVERITY_RANK else (v or None)


def _when(v) -> str | None:
    v = _s(v, 40)
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def normalize(key: str, item: dict, first_seen: datetime | None = None) -> dict:
    src = (_s(item.get("source"), 64) or "").lower()
    desc = _s(item.get("description"), 2000)
    hosts = item.get("hosts") if isinstance(item.get("hosts"), list) else []
    detected = _when(item.get("detected_at") or item.get("timestamp") or item.get("created_at"))
    status = _s(item.get("status"), 32)
    if not status and src == "crowdstrike":
        status = "new"  # older CrowdStrike pulls only ever asked for new alerts
    link = _s(item.get("link"), 1000)
    tactic_id = (_s(item.get("tactic_id"), 8) or "").upper()
    return {
        "id": key,
        "source": src or None,
        "source_code": SOURCE_CODES.get(src, src.upper()[:8] or "?"),
        # Without a title: a short description, else what it did (its technique), never a whole paragraph
        "title": _s(item.get("title")) or _s(item.get("name")) or _s(item.get("attack"))
                 or (desc if desc and len(desc) <= 120 else None) or _s(item.get("technique"), 128)
                 or (desc[:120].rsplit(" ", 1)[0] + "..." if desc else None),
        "description": desc,
        "severity": _severity(item.get("severity")),
        "status": status.lower().replace(" ", "_") if status else None,
        "detected_at": detected or (first_seen.isoformat() if first_seen else None),
        "detected_estimated": not detected,
        "hostname": _s(item.get("hostname") or item.get("device_hostname") or item.get("source_asset")
                       or (hosts[0] if hosts else None), 253),
        "tactic": _s(item.get("tactic"), 128),
        "tactic_id": tactic_id if _TACTIC.match(tactic_id) else None,
        "technique": _s(item.get("technique"), 128) or _s(item.get("classification"), 128) or _s(item.get("category"), 128),
        "technique_id": _technique(item),
        "link": link if link and _LINK.match(link) else None,
        "aggregate_id": _s(item.get("aggregate_id"), 200),
        "user_key": _s(item.get("user_key"), 128),   # keyed hash of the alert's user, for tying alerts together
        "has_detail": bool(item.get("detail_enc")),
    }


def matches(a: dict, q: str) -> bool:
    q = q.lower()
    return any(q in (a.get(f) or "").lower() for f in
               ("title", "description", "hostname", "tactic", "technique", "technique_id", "tactic_id", "source_code",
                "source", "status", "id"))


def sort_key(field: str):
    if field == "severity":
        return lambda a: (SEVERITY_RANK.get(a.get("severity") or "", 0), a.get("detected_at") or "")
    return lambda a: ((a.get(field) or "").lower(), SEVERITY_RANK.get(a.get("severity") or "", 0))
