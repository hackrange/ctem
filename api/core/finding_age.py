"""How old a vulnerability is: days from when it was first found until today (or until it was fixed).

One definition for every list, export, dashboard and control check. An open finding ages until today; a closed one
stops at its last sighting. SLA days are the install's setting (api/core/sla.py, Vulnerabilities > Change SLAs)."""
from __future__ import annotations

from datetime import datetime, timezone

OPEN = {"open", "in_progress"}


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days(first: datetime | None, until: datetime | None = None) -> int | None:
    """Whole days from first until `until` (default now); None when first is unknown."""
    first = _utc(first)
    if first is None:
        return None
    end = _utc(until) or datetime.now(timezone.utc)
    return max(0, (end - first).days)


def severity(cvss: float | None) -> str:
    c = cvss or 0.0
    return "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"


def view(first: datetime | None, last: datetime | None, status: str, cvss: float | None) -> dict:
    """age_days, until ("today" or "fixed"), the SLA for its severity, and whether an open one is past it."""
    from api.core.vuln_dashboard import SLA_DAYS
    is_open = status in OPEN
    age = days(first, None if is_open else last)
    sla = SLA_DAYS.get(severity(cvss))
    return {"age_days": age, "age_until": "today" if is_open else "fixed", "sla_days": sla,
            "past_sla": bool(is_open and age is not None and sla is not None and age > sla)}
