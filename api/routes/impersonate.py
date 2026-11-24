"""Admin > Users > View as: start, check and stop (rules in api/auth/impersonation.py)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth import impersonation, step_up
from api.auth.middleware import get_current_user
from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(tags=["admin"])


class StartBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=4, max_length=200, pattern=r"^[^\x00-\x1f<>]+$")


@router.post("/api/v1/admin/users/{user_id}/impersonate")
async def start(user_id: uuid.UUID, body: StartBody, request: Request, admin: User = Depends(require_admin),
                db: AsyncSession = Depends(get_session)):
    step_up.browser_only(request)
    if request.session.get("user_id") != str(admin.id):
        raise HTTPException(403, detail="Use the web interface for this action")
    if str(user_id) == str(admin.id):
        raise HTTPException(400, detail="That's you.")
    target = (await db.execute(select(User).where(User.id == str(user_id)).options(selectinload(User.roles)))).scalar_one_or_none()
    if target is None:
        raise HTTPException(404)
    why = impersonation.can_be_viewed(target)
    if why:
        raise HTTPException(400, detail=why)
    until = impersonation.start(request, admin, target)
    await impersonation._audit(db, admin, "impersonate.start", str(target.id),
                               f"Started viewing as {target.username} (read-only, 30 min): {body.reason.strip()}", request)
    return {"viewing_as": target.username, "until": until}


@router.get("/api/v1/impersonate")
async def status(request: Request, user: User = Depends(get_current_user)):
    by = getattr(request.state, "impersonator", None)
    if by is None:
        return {"active": False}
    return {"active": True, "viewing_as": user.username, "by": by.username,
            "until": getattr(request.state, "impersonating_until", None)}


@router.post("/api/v1/impersonate/stop")
async def stop(request: Request, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_session)):
    by = getattr(request.state, "impersonator", None)
    impersonation.end(request)
    if by is not None:
        await impersonation._audit(db, by, "impersonate.stop", str(user.id), f"Stopped viewing as {user.username}", request)
    return {"active": False}
