"""People discovered in AD/LDAP (Discovered Users page). Not CTEM accounts; those are under /admin/users."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.rbac import require_cyber_or_admin
from api.core.accounts import directory_person
from api.core.db import get_session
from api.core.user_devices import NO_DEVICES, device_counts
from api.models.user import User
from api.routes.user_view import user_summary

router = APIRouter(prefix="/api/v1/directory", tags=["directory"])


@router.get("/users")
async def list_directory_users(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=256, description="Username or UPN search"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    from api.core.encryption import search_hash
    from api.models.risk import RiskScore

    where = [directory_person()]
    if q:
        where.append(or_(User.username.ilike(f"%{q}%"), User.upn_hash == search_hash(q.strip().lower())))
    total = (await db.execute(select(func.count(User.id)).where(*where))).scalar_one()
    users = (await db.execute(select(User).options(selectinload(User.roles)).where(*where).order_by(User.username)
                              .offset(offset).limit(limit))).scalars().all()
    ids = [u.id for u in users]
    scores = {s.entity_id: s for s in (await db.execute(
        select(RiskScore).where(RiskScore.entity_type == "user", RiskScore.entity_id.in_(ids)))).scalars()}
    devices = await device_counts(db, ids)
    return {"users": [{**user_summary(u, scores.get(u.id)), **devices.get(u.id, NO_DEVICES)} for u in users],
            "total": total}
