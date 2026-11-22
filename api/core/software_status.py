"""What a title's status is on one asset: its own (approved, unauthorized, unreviewed), unless an active
exception for that asset says otherwise (allowed here, or not allowed here). Expired exceptions don't count."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import and_, exists, or_, select


def exception_is(decision: str):
    """An active exception with this decision for the install's title and asset (correlated to SoftwareInstall)."""
    from api.models.software import SoftwareException as E
    from api.models.software import SoftwareInstall as I
    return exists(select(E.id).where(E.title_id == I.title_id, E.device_id == I.device_id, E.decision == decision,
                                     or_(E.expires_at.is_(None), E.expires_at > datetime.now(timezone.utc))))


def unauthorized_here():
    """Installs that are unauthorized on their asset: the title is unauthorized and not allowed there, or the
    asset has a 'not allowed here' exception."""
    from api.models.software import SoftwareTitle as T
    return or_(and_(T.status == "unauthorized", ~exception_is("allowed")), exception_is("denied"))


def effective(title_status: str, exc) -> str:
    """The status on one asset, given its exception (or None)."""
    if exc is not None and (exc.expires_at is None or _aware(exc.expires_at) > datetime.now(timezone.utc)):
        return "approved" if exc.decision == "allowed" else "unauthorized"
    return title_status


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
