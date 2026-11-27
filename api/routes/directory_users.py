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


# The summary cards, each also a filter on the list (?card=): the same rule counts and filters
CARDS = ("high_risk", "no_mfa", "privileged", "service", "idv")
PRIVILEGED = {"domain admins", "enterprise admins", "schema admins", "administrators"}


def _group(g) -> str:
    """An AD group as its own name, lower case: CN=Domain Admins,OU=...,DC=... is "domain admins"."""
    g = str(g or "")
    return (g[3:].split(",")[0] if g[:3].upper() == "CN=" else g).strip().lower()


async def _encrypted_cards(db: AsyncSession) -> dict[str, set]:
    """Cards whose facts are encrypted at rest (AD groups, Okta factors), so SQL can't test them: read those columns
    for the directory's people and test here. No MFA means no Okta factor enrolled and no CTEM authenticator."""
    rows = await db.execute(select(User.id, User.ad_groups, User.idp, User.totp_enabled).where(directory_person()))
    out = {"privileged": set(), "no_mfa": set()}
    for uid, groups, idp, totp in rows.all():
        if any(_group(g) in PRIVILEGED for g in groups or []):
            out["privileged"].add(uid)
        if not totp and not (idp or {}).get("factors"):
            out["no_mfa"].add(uid)
    return out


def _sql_card(card: str):
    from api.models.risk import RiskScore
    if card == "high_risk":
        return User.id.in_(select(RiskScore.entity_id).where(RiskScore.entity_type == "user", RiskScore.grade.in_(("F", "D"))))
    if card == "service":
        return User.is_service_account.is_(True)
    return User.idv_verified_at.is_not(None)   # idv


@router.get("/users/summary")
async def directory_summary(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """The cards' counts over every discovered person, not one page of them."""
    count = lambda *w: db.execute(select(func.count(User.id)).where(directory_person(), *w))  # noqa: E731
    enc = await _encrypted_cards(db)
    out = {"total": (await count()).scalar_one(), **{k: len(v) for k, v in enc.items()}}
    for c in ("high_risk", "service", "idv"):
        out[c] = (await count(_sql_card(c))).scalar_one()
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
    stale_days: int | None = Query(None, ge=1, le=3650, description="Enabled AD accounts with no logon in this many days"),
    card: Literal[CARDS] | None = Query(None, description="Only the people one summary card counts"),
    grade: str | None = Query(None, pattern="^[ABCDF]$", description="Risk grade"),
):
    from api.core.encryption import search_hash
    from api.models.risk import RiskScore

    where = [directory_person()]
    if q:
        key = search_hash(q.strip().lower())   # a UPN whole, or its first half (jane.doe)
        where.append(or_(User.username.ilike(f"%{q}%"), User.upn_hash == key, User.upn_local_hash == key,
                         User.id.in_(await _by_name_or_phone(db, q))))
    now = datetime.now(timezone.utc)
    if expiry == "expiring":
        where += [User.ad_pwd_never_expires.is_not(True), User.ad_pwd_expires > now, User.ad_pwd_expires <= now + timedelta(days=within)]
    elif expiry == "expired":
        where.append(User.ad_pwd_expired.is_(True))
    elif expiry == "never":
        where.append(User.ad_pwd_never_expires.is_(True))
    if stale_days:   # the same rule the dashboard's stale-account counts use
        from api.dashboards.m_directory import stale_users
        where += stale_users(stale_days)
    if card in ("privileged", "no_mfa"):
        where.append(User.id.in_(sorted((await _encrypted_cards(db))[card])))
    elif card:
        where.append(_sql_card(card))
    if grade:
        where.append(User.id.in_(select(RiskScore.entity_id).where(RiskScore.entity_type == "user", RiskScore.grade == grade)))
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
    from api.core.manager import manager_of
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
            "manager": await manager_of(db, u),   # from the directory (AD through Okta): name, title, email
            "devices": [{"id": str(d.id), "hostname": d.hostname, "ip": d.ip, "type": d.device_type.value if d.device_type else None,
                         "last_seen": when(d.last_seen), "how": "assigned" if d.id in assigned else "signs in"} for d in rows]}
