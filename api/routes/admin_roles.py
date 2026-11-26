"""Admin > Roles: who holds a role (click a role to see its members)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.user import Role, User, UserRole

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
LIMIT = 1000


@router.get("/roles/{role_name}/members")
async def role_members(role_name: str = Path(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$"),
                       _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one_or_none()
    if role is None:
        raise HTTPException(404)
    rows = (await db.execute(select(User).join(UserRole, UserRole.user_id == User.id).where(UserRole.role_name == role_name)
                             .order_by(User.username).limit(LIMIT + 1))).scalars().all()
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {"role": {"name": role.name, "display_name": role.display_name, "description": role.description},
            "members": [{"id": u.id, "username": u.username, "name": u.display_name, "email": u.email,
                         "kind": "service account" if u.is_service_account else ("local" if u.is_local else "SSO"),
                         "active": bool(u.is_active and not u.is_locked), "last_login": iso(u.last_login)} for u in rows[:LIMIT]],
            "more": len(rows) > LIMIT}
