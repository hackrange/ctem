"""Unlock an account, and repair one changed outside CTEM (its seal no longer matches, api/auth/account_seal.py). Nothing it
held is trusted: the admin picks its roles and whether it's active, a local account gets a new one-time password,
its authenticator and recovery codes go, and an SSO account loses its identity link (the person's next SSO sign-in
makes a fresh account). Admins only, with a fresh "confirm it's you"; audited."""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import account_seal, local, step_up
from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import User, UserRole

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class Repair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    roles: list[Annotated[str, Field(pattern=r"^[a-z0-9_]{2,64}$")]] = Field(max_length=20)
    active: bool = False
    password: str | None = Field(None, min_length=12, max_length=1024)   # required for a local account


@router.post("/users/{user_id}/repair")
async def repair_account(user_id: uuid.UUID, body: Repair, request: Request, admin: User = Depends(require_admin),
                         db: AsyncSession = Depends(get_session)):
    step_up.require(request, admin)
    from api.routes.admin import _require_roles_exist
    user = (await db.execute(select(User).where(User.id == str(user_id)))).scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    if str(user.id) == str(admin.id):
        raise HTTPException(400, detail="Another admin repairs your account")
    await _require_roles_exist(body.roles, db)
    if user.is_local and not body.password:
        raise HTTPException(400, detail="Set a new one-time password for this local account")
    roles = sorted(set(body.roles))
    await db.execute(delete(UserRole).where(UserRole.user_id == str(user.id)))
    for r in roles:
        db.add(UserRole(user_id=str(user.id), role_name=r))
    user.totp_enabled, user.totp_secret, user.totp_seal, user.recovery_codes = False, None, None, None
    user.is_active, user.is_locked = body.active, False
    if user.is_local:
        user.password_hash = local.hash_password(body.password)
        local.one_time_password(user)
    else:
        user.password_hash, user.oidc_sub, user.oidc_issuer = None, None, None
        user.password_change_required, user.password_expires_at = False, None
    from api.auth import sessions
    sessions.new_password(request, user)   # whoever holds a session for it is out
    await account_seal.reseal(db, user, roles)
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="account.repaired",
                    resource_type="user", resource_id=str(user.id),
                    detail=f"{user.username}: roles {', '.join(roles) or 'none'}, {'active' if body.active else 'inactive'}"[:300]))
    await db.commit()
    return {"repaired": True, "roles": roles, "active": user.is_active}


@router.patch("/users/{user_id}/unlock")
async def unlock_user(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Clear both Redis lockout and DB flag. Admin only."""
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    roles = await account_seal.checked(db, user)
    await local.admin_unlock_user(user.username, db_flag=False)
    user.is_locked, user.locked_reason = False, None
    await account_seal.reseal(db, user, roles)
    from api.routes.admin import _audit
    await _audit(admin, "unlock_user", "user", str(user_id), f"Unlocked {user.username}", db)
    return {"unlocked": True}
