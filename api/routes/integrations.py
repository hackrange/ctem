"""Integration CRUD: configure connectors, trigger syncs, view status."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.auth.rbac import require_admin, require_cyber_or_admin
from api.core.db import get_session
from api.models.integration import IntegrationConfig, SyncJob, Vendor
from api.models.user import User

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("")
async def list_integrations(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).order_by(IntegrationConfig.vendor))
    return {"integrations": [_summary(i) for i in result.scalars()]}


@router.post("")
async def create_integration(
    body: CreateIntegrationRequest,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    cfg = IntegrationConfig(
        vendor=body.vendor,
        name=body.name,
        is_enabled=body.is_enabled,
        config=body.config,
        sync_schedule=body.sync_schedule,
    )
    db.add(cfg)
    await db.commit()
    return _summary(cfg)


@router.get("/{integration_id}")
async def get_integration(
    integration_id: uuid.UUID,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == integration_id))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    return _summary(cfg)


@router.put("/{integration_id}")
async def update_integration(
    integration_id: uuid.UUID,
    body: UpdateIntegrationRequest,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == integration_id))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    if body.name is not None:
        cfg.name = body.name
    if body.is_enabled is not None:
        cfg.is_enabled = body.is_enabled
    if body.config is not None:
        cfg.config = body.config
    if body.sync_schedule is not None:
        cfg.sync_schedule = body.sync_schedule
    await db.commit()
    return _summary(cfg)


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == integration_id))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    await db.delete(cfg)
    await db.commit()
    return {"deleted": True}


@router.post("/{integration_id}/sync")
async def trigger_sync(
    integration_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == integration_id, IntegrationConfig.is_enabled == True))  # noqa: E712
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    from api.core.tasks import sync_integration
    task = sync_integration.delay(str(integration_id))
    return {"task_id": task.id, "status": "queued"}


@router.post("/{integration_id}/test")
async def test_connection(
    integration_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == integration_id))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    from api.integrations.base import get_connector
    connector = get_connector(cfg.vendor.value, cfg.config or {})
    ok = await connector.test_connection()
    return {"connected": ok}


@router.get("/{integration_id}/jobs")
async def list_sync_jobs(
    integration_id: uuid.UUID,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(SyncJob)
        .where(SyncJob.integration_id == str(integration_id))
        .order_by(SyncJob.created_at.desc())
        .limit(50)
    )
    jobs = result.scalars().all()
    return {"jobs": [{"id": str(j.id), "status": j.status.value, "started": j.started_at.isoformat() if j.started_at else None, "records": j.records_imported, "error": j.error_message} for j in jobs]}


def _summary(cfg: IntegrationConfig) -> dict:
    return {
        "id": str(cfg.id),
        "vendor": cfg.vendor.value,
        "name": cfg.name,
        "is_enabled": cfg.is_enabled,
        "last_sync_at": cfg.last_sync_at.isoformat() if cfg.last_sync_at else None,
        "last_sync_status": cfg.last_sync_status.value if cfg.last_sync_status else None,
        "sync_schedule": cfg.sync_schedule,
    }


class CreateIntegrationRequest(BaseModel):
    vendor: Vendor
    name: str
    config: dict = {}
    is_enabled: bool = True
    sync_schedule: str | None = None


class UpdateIntegrationRequest(BaseModel):
    name: str | None = None
    is_enabled: bool | None = None
    config: dict | None = None
    sync_schedule: str | None = None
