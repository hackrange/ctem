"""Pause and resume integration syncing (Settings > Integrations), for admins; audited (api/core/sync_pause.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core import sync_pause
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


class PauseBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    paused: bool
    minutes: int | None = None   # one of sync_pause.DURATIONS, or None for until resumed


@router.get("/sync-pause")
async def get_pause(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    return {"paused": await sync_pause.state(db), "durations": list(sync_pause.DURATIONS)}


@router.put("/sync-pause")
async def put_pause(body: PauseBody, u: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    if body.paused and body.minutes is not None and body.minutes not in sync_pause.DURATIONS:
        raise HTTPException(400, detail="Choose 30 minutes, 1 hour, 4 hours or until resumed")
    if body.paused:
        v = await sync_pause.set_pause(db, u.username, body.minutes)
        detail = f"until {v['until']}" if v["until"] else "until resumed"
    else:
        await sync_pause.resume(db)
        detail = "resumed"
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username,
                    action="integrations.sync_paused" if body.paused else "integrations.sync_resumed",
                    resource_type="integration", resource_id="all", detail=detail[:300]))
    await db.commit()
    return {"paused": await sync_pause.state(db), "durations": list(sync_pause.DURATIONS)}
