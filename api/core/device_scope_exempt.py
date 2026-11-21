"""Not In Scope: a device an admin or cyber analyst has excluded, with a justification, until a date.
EDR containment works the same way: a host the EDR has network-isolated can't be reached, so while it
is contained its vulnerabilities don't count either (reachability is 0).

While the exclusion or containment runs, the device's vulnerabilities don't count: its risk is 0, it has no open findings
in the rollups, and it is left out of vulnerability affected counts and the vulnerability GRC checks.
The findings are still stored and shown (dimmed), so nothing is lost when the exclusion ends.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import and_, or_, select

MAX_DAYS = 365   # an exclusion has to be renewed at least yearly


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_exempt(device) -> bool:
    until = _aware(getattr(device, "scope_exempt_until", None))
    return until is not None and until > now()


def is_contained(device) -> bool:
    """Network-isolated by the EDR right now (Falcon "contained" or "lift containment pending")."""
    return bool(getattr(device, "edr_contained", False))


def counts(device) -> bool:
    """Whether this device's vulnerabilities count: not excluded and not contained."""
    return not (is_exempt(device) or is_contained(device))


def in_scope():
    """SQL condition on Device: no running exclusion and not contained by the EDR."""
    from api.models.device import Device
    return and_(or_(Device.scope_exempt_until.is_(None), Device.scope_exempt_until <= now()),
                Device.edr_contained.is_not(True))


def in_scope_findings():
    """SQL condition on Finding: its device has no running exclusion and isn't contained by the EDR."""
    from api.models.device import Device
    from api.models.vuln import Finding
    return Finding.device_id.not_in(select(Device.id).where(
        or_(Device.scope_exempt_until > now(), Device.edr_contained.is_(True))))


def view(device) -> dict | None:
    if not is_exempt(device):
        return None
    at = _aware(device.scope_exempt_at)
    return {"until": _aware(device.scope_exempt_until).isoformat(), "reason": device.scope_exempt_reason,
            "by": device.scope_exempt_by, "at": at.isoformat() if at else None}
