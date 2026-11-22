"""Admin accounts signing in to computers: privileged accounts (adm, svc_, sulocal_ and the like) seen logging on
interactively to workstations and servers, from the EDR's sign-in history (the last sign-in and the recent ones).

Admin and service accounts should not sign in to ordinary computers: their credentials can be lifted from memory
there. Computers where it is expected (jump servers, admin workstations) are left out with a curated rule's device
scope; the account names looked for can be changed with a curated rule's account_patterns."""
from __future__ import annotations

import fnmatch
from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.device_scope_exempt import in_scope
from api.grc.checks import EDR, Check, Outcome, Threshold, grade_low, now, register
from api.models.device import Device, DeviceType
from api.rules.apply import device_scope

MAX_ROWS = 50000
DEFAULT_PATTERNS = ("adm*", "svc_*", "sulocal_*")


def bare(name: str) -> str:
    """The account name without its domain: ACME\\adm.pat and adm.pat@acme.example are both adm.pat."""
    n = str(name or "").strip()
    n = n.rsplit("\\", 1)[-1]
    return n.split("@", 1)[0].strip().lower()


def matches(name: str, patterns) -> str | None:
    """The first pattern (case-insensitive, * and ?) this account name matches, or None."""
    b = bare(name)
    if not b:
        return None
    for p in patterns:
        if fnmatch.fnmatchcase(b, p.lower().replace("[", "[[]")):
            return p
    return None


async def _admin_logons(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    patterns = tuple(t.get("_account_patterns") or DEFAULT_PATTERNS)
    types = [DeviceType.workstation] + ([DeviceType.server] if t["include_servers"] else [])
    cut = now() - timedelta(days=t["seen_days"])
    devs = (await db.execute(select(Device).where(
        Device.device_type.in_(types), device_scope(), in_scope(),
        or_(Device.edr_last_seen >= cut, Device.last_seen >= cut)))).scalars().all()
    hits, by_pattern, accounts = [], {p: 0 for p in patterns}, set()
    for d in devs:   # sign-in names are encrypted at rest, so they're matched here, not in SQL
        names = [n for n in [d.last_login_user, *(d.recent_logins or [])] if isinstance(n, str) and n]
        found = {}
        for n in names:
            p = matches(n, patterns)
            if p and bare(n) not in found:
                found[bare(n)] = (n, p)
        if found:
            hits.append((d, found))
            for b, (_, p) in found.items():
                by_pattern[p] += 1
                accounts.add(b)
    n = len(hits)
    out = Outcome(grade_low(n, 0, t["warn_max"]),
                  f"{n:,} of {len(devs):,} active {'workstations and servers' if t['include_servers'] else 'workstations'} "
                  f"had an admin account sign in ({len(accounts):,} accounts matching {', '.join(patterns)})",
                  {"computers": len(devs), "computers_with_admin_logons": n, "admin_accounts": len(accounts),
                   "sign_ins_by_pattern": by_pattern, "patterns": list(patterns)})
    if detail:
        out.columns = ["hostname", "device_type", "accounts", "last_sign_in", "last_seen", "patterns"]
        rows = []
        for d, found in sorted(hits, key=lambda h: h[0].hostname or ""):
            last = bare(d.last_login_user or "")
            rows.append({"device_id": str(d.id), "hostname": d.hostname, "device_type": d.device_type.value,
                         "accounts": ", ".join(sorted(v[0] for v in found.values()))[:500],
                         "last_sign_in": d.last_login_user if last in found else "",
                         "last_seen": (d.edr_last_seen or d.last_seen).isoformat() if (d.edr_last_seen or d.last_seen) else "",
                         "patterns": ", ".join(sorted({v[1] for v in found.values()}))})
        out.rows = rows[:MAX_ROWS]
    return out


register(Check(
    "ctem_admin_local_logons", "Admin accounts signing in to computers",
    "Workstations and servers where an admin or service account (adm, svc_, sulocal_...) signed in interactively", 1, EDR,
    ("NIST 800-53 AC-6(5)", "NIST 800-53 AC-6(9)", "CIS 5.4", "ISO 27001 A.8.2", "MITRE ATT&CK T1078.003"),
    {"seen_days": Threshold(30, 1, 365, "computers seen by the EDR within this many days"),
     "include_servers": Threshold(1, 0, 1, "1 = servers too (leave jump servers out with a rule); 0 = workstations only"),
     "warn_max": Threshold(0, 0, 100000, "computers tolerated as a warning instead of a fail")},
    _admin_logons, device_scoped=True, account_patterns=DEFAULT_PATTERNS))
