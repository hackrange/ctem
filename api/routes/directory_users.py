"""People discovered in AD/LDAP (Discovered Users page). Not CTEM accounts; those are under /admin/users."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.rbac import require_cyber_or_admin
from api.core.accounts import directory_person
from api.core.db import get_session
from api.core.user_devices import NO_DEVICES, device_counts
from api.models.user import User
from api.routes.user_view import user_summary

router = APIRouter(prefix="/api/v1/directory", tags=["directory"])


def _digits(v: str | None) -> str:
    return "".join(c for c in (v or "") if c.isdigit())


async def _by_name_or_phone(db: AsyncSession, q: str) -> list[str]:
    """Names and phone numbers are encrypted at rest, so SQL can't search them: read just those columns for the
    directory's people and match here. Every word must be in the name ("jane doe", "doe j"); a phone matches on its
    digits ("555-0101", "(555) 010 1999"), 4 digits or more."""
    words = [w for w in q.strip().lower().split() if w][:4]
    digits = _digits(q) if len(_digits(q)) >= 4 and not any(c.isalpha() for c in q) else ""
    if not words:
        return []
    rows = await db.execute(select(User.id, User.first_name, User.last_name, User.display_name, User.phone, User.mobile)
                            .where(directory_person()))
    out = []
    for uid, first, last, shown, phone, mobile in rows.all():
        if digits and (digits in _digits(phone) or digits in _digits(mobile)):
            out.append(uid)
            continue
        name = f"{first or ''} {last or ''} {shown or ''}".lower()
        if not digits and all(w in name for w in words):
            out.append(uid)
    return out


@router.get("/users")
async def list_directory_users(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=256, description="Username or UPN search"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    expiry: Literal["expiring", "expired", "never"] | None = Query(None, alias="pwd", description="AD password: expiring soon, expired, never expires"),
    within: int = Query(14, ge=1, le=365, description="Days ahead for pwd=expiring"),
):
    from api.core.encryption import search_hash
    from api.models.risk import RiskScore

    where = [directory_person()]
    if q:
        where.append(or_(User.username.ilike(f"%{q}%"), User.upn_hash == search_hash(q.strip().lower()),
                         User.id.in_(await _by_name_or_phone(db, q))))
    now = datetime.now(timezone.utc)
    if expiry == "expiring":
        where += [User.ad_pwd_never_expires.is_not(True), User.ad_pwd_expires > now, User.ad_pwd_expires <= now + timedelta(days=within)]
    elif expiry == "expired":
        where.append(User.ad_pwd_expired.is_(True))
    elif expiry == "never":
        where.append(User.ad_pwd_never_expires.is_(True))
    order = (User.ad_pwd_expires, User.username) if expiry == "expiring" else (User.username,)
    total = (await db.execute(select(func.count(User.id)).where(*where))).scalar_one()
    users = (await db.execute(select(User).options(selectinload(User.roles)).where(*where).order_by(*order)
                              .offset(offset).limit(limit))).scalars().all()
    ids = [u.id for u in users]
    scores = {s.entity_id: s for s in (await db.execute(
        select(RiskScore).where(RiskScore.entity_type == "user", RiskScore.entity_id.in_(ids)))).scalars()}
    devices = await device_counts(db, ids)
    return {"users": [{**user_summary(u, scores.get(u.id)), **devices.get(u.id, NO_DEVICES)} for u in users],
            "total": total}


@router.get("/users/{user_id}")
async def directory_user(user_id: uuid.UUID, _: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """One discovered person in full: profile, where they work, AD account and password, groups, machines, risk."""
    from api.models.device import Device, DeviceAssignment
    from api.models.risk import RiskScore

    u = (await db.execute(select(User).options(selectinload(User.roles))
                          .where(User.id == str(user_id), directory_person()))).scalar_one_or_none()
    if u is None:
        raise HTTPException(404)   # also for a CTEM sign-in account: those are under Admin > Users
    risk = (await db.execute(select(RiskScore).where(RiskScore.entity_type == "user", RiskScore.entity_id == u.id)
                             .order_by(RiskScore.calculated_at.desc()).limit(1))).scalars().first()
    assigned = set((await db.execute(select(DeviceAssignment.device_id).where(DeviceAssignment.user_id == u.id))).scalars())
    rows = (await db.execute(select(Device).where(or_(Device.id.in_(assigned) if assigned else false(), Device.owner_user_id == u.id))
                             .order_by(Device.last_seen.desc().nulls_last()).limit(50))).scalars().all()
    try:
        factors = json.loads(risk.score_breakdown) if risk and risk.score_breakdown else None
    except ValueError:
        factors = None
    when = lambda v: v.isoformat() if v else None  # noqa: E731
    return {**user_summary(u, risk),
            "where": {"office": u.office, "city": u.city, "state": u.state, "postal_code": u.postal_code,
                      "department": u.department},
            "risk_factors": factors if isinstance(factors, (dict, list)) else None,
            "risk_at": when(risk.calculated_at) if risk else None,
            "devices": [{"id": str(d.id), "hostname": d.hostname, "ip": d.ip, "type": d.device_type.value if d.device_type else None,
                         "last_seen": when(d.last_seen), "how": "assigned" if d.id in assigned else "signs in"} for d in rows]}
