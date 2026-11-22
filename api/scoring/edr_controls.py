"""What an EDR's policies on a host actually do, for the score and its reasons (api/scoring/compensating.py).

From the stored policies (api/models/edr_policy.py): whether the prevention policy blocks or only detects, which
exploit mitigations are on, whether USB storage is blocked, and what the host firewall does to a finding's port."""
from __future__ import annotations

import re
import time

_ML_ON = {"CAUTIOUS", "MODERATE", "AGGRESSIVE", "EXTRA_AGGRESSIVE"}
# A toggle that stops something, by its category or its own name (Falcon: "Execution Blocking", "Quarantine"...)
_BLOCKING = re.compile(r"\b(prevent\w*|quarantine|block\w*|kill|ransomware)\b", re.I)
_EXPLOIT = re.compile(r"exploit mitigation|force dep|force aslr|heap spray|null page|seh overwrite", re.I)
MEMORY_FLAW = re.compile(r"buffer overflow|heap overflow|stack overflow|use[- ]after[- ]free|out[- ]of[- ]bounds write|"
                         r"memory corruption|type confusion|double free|integer overflow|heap[- ]based|stack[- ]based", re.I)
VENDOR = {"crowdstrike": "Falcon", "sentinelone": "SentinelOne", "msdefender": "Defender", "cortex_xdr": "Cortex XDR"}

_cache: dict = {"at": 0.0, "rows": {}}


async def policies(db) -> dict:
    """Every stored policy by (vendor, policy id, kind), cached for a minute: a rescore reads it for each host."""
    if time.monotonic() - _cache["at"] < 60:
        return _cache["rows"]
    from sqlalchemy import select

    from api.models.edr_policy import EdrPolicy
    rows = {(p.vendor, p.policy_id, p.kind): p for p in (await db.execute(select(EdrPolicy))).scalars()}
    _cache.update(at=time.monotonic(), rows=rows)
    return rows


def prevention(policy) -> dict | None:
    """{blocking: [what blocks], exploit: [mitigations on], name} from a prevention policy, or None if unknown."""
    if policy is None or not policy.enabled:
        return None if policy is None else {"blocking": [], "exploit": [], "name": policy.name}
    blocking, exploit = [], []
    for sid, st in ((policy.body or {}).get("settings") or {}).items():
        name, cat, val = st.get("name") or sid, st.get("category") or "", st.get("value")
        if isinstance(val, str) and val.upper() in _ML_ON:
            blocking.append(f"{name} ({val.lower().replace('_', ' ')})")
        elif val is True and _EXPLOIT.search(f"{cat} {name}"):
            exploit.append(name)
        elif val is True and _BLOCKING.search(f"{cat} {name}"):
            blocking.append(name)
    return {"blocking": blocking, "exploit": exploit, "name": policy.name}


def _ports(spec: str) -> list[tuple[int, str]]:
    out = []
    for p in (spec or "").split():
        num, _, proto = p.partition("/")
        if num.isdigit():
            out.append((int(num), (proto or "tcp").upper()))
    return out


def _in(port: int, ranges) -> bool:
    return not ranges or any(a <= port <= (b or a) for a, b in ranges)


def _any_remote(addrs) -> bool:
    return not addrs or any(a in ("*", "0.0.0.0/0", "::/0") for a in addrs)


def firewall(policy, ports: str | None) -> tuple[float, str] | None:
    """What an enforced host firewall does to inbound traffic on a finding's listening ports: (factor, reason), or
    None when it doesn't change anything (not enforced, no ports, or a port open to anyone)."""
    if policy is None or not ports:
        return None
    b = policy.body or {}
    if not (policy.enabled and b.get("enforce") and not b.get("test_mode")):
        return None
    verdicts = []
    for port, proto in _ports(ports):
        hit = None
        for r in b.get("rules") or []:
            if not r.get("enabled") or r.get("monitor_only") or str(r.get("direction") or "").upper() not in ("IN", "BOTH"):
                continue
            rp = str(r.get("protocol") or "Any").upper()
            if rp not in ("ANY", "*", proto) or not _in(port, r.get("local_port")):
                continue
            hit = r
            break
        if hit is None:
            act = str(b.get("default_inbound") or "").upper()
            if act not in ("DENY", "BLOCK"):
                return None   # nothing blocks it: open
            verdicts.append(("block", f"{port}/{proto.lower()} by the default inbound block"))
            continue
        act = str(hit.get("action") or "").upper()
        if act in ("DENY", "BLOCK"):
            verdicts.append(("block", f"{port}/{proto.lower()} by rule \"{hit.get('name') or 'unnamed'}\""))
        elif _any_remote(hit.get("remote_address")):
            return None       # allowed from anywhere
        else:
            src = ", ".join((hit.get("remote_address") or [])[:3])
            verdicts.append(("restricted", f"{port}/{proto.lower()} only from {src} (rule \"{hit.get('name') or 'unnamed'}\")"))
    if not verdicts:
        return None
    if all(v == "block" for v, _ in verdicts):
        return 0.5, "Host firewall blocks inbound " + "; ".join(w for _, w in verdicts) + " (-50%)"
    return 0.7, "Host firewall allows inbound " + "; ".join(w for _, w in verdicts) + " (-30%)"
