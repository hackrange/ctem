"""Truncate an integration's data (Settings > Integrations > Truncate). Admins only, confirmed by typing the
integration's name, audited, and run in the background (api/core/integration_truncate.py)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core import integration_truncate as tr
from api.core.db import get_session
from api.models.integration import IntegrationConfig
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


class TruncateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: str = Field(min_length=1, max_length=128)


async def _cfg(db, integration_id: uuid.UUID) -> IntegrationConfig:
    cfg = await db.get(IntegrationConfig, str(integration_id))
    if cfg is None:
        raise HTTPException(404)
    return cfg


@router.get("/{integration_id}/truncate")
async def truncate_preview(integration_id: uuid.UUID, _: User = Depends(require_admin),
                           db: AsyncSession = Depends(get_session)):
    cfg = await _cfg(db, integration_id)
    if not tr.truncatable(cfg.vendor.value):
        return {"truncatable": False, "running": False}
    return {**await tr.preview(db, cfg), "name": cfg.name, "running": await tr.running(str(cfg.id))}


@router.post("/{integration_id}/truncate", status_code=202)
async def truncate(integration_id: uuid.UUID, body: TruncateBody, u: User = Depends(require_admin),
                   db: AsyncSession = Depends(get_session)):
    cfg = await _cfg(db, integration_id)
    if not tr.truncatable(cfg.vendor.value):
        raise HTTPException(400, detail="This integration doesn't report data")
    if body.confirm.strip() != (cfg.name or "").strip():
        raise HTTPException(400, detail="Type the integration's name exactly to confirm")
    if await tr.running(str(cfg.id)):
        raise HTTPException(409, detail="A truncate of this source is already running")
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="integration.truncate_requested",
                    resource_type="integration", resource_id=str(cfg.id), detail=f"{cfg.name} ({cfg.vendor.value})"[:300]))
    await db.commit()
    from api.core.tasks import truncate_integration
    truncate_integration.delay(str(cfg.id), u.username)
    return {"status": "queued"}
