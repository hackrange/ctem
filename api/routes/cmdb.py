"""CMDB endpoints: list, ServiceNow sync, and JSON export."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import get_accessible_device_tag_ids, require_cyber_or_admin
from api.core.db import get_session
from api.models.device import Device, DeviceTag
from api.models.user import User

log = logging.getLogger("open-ctem.cmdb")
router = APIRouter(prefix="/api/v1/cmdb", tags=["cmdb"])

@router.get("")
async def list_cmdb(
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    limit: int = Query(200, le=5000),
    offset: int = 0,
):
    """CMDB record list for the UI table, with ServiceNow integration status."""
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AppSetting
    from sqlalchemy import func

    tag_ids = await get_accessible_device_tag_ids(current_user, db)
    stmt = (
        select(Device)
        .options(
            selectinload(Device.owner),
            selectinload(Device.tags).selectinload(DeviceTag.tag),
        )
        .order_by(Device.hostname)
    )
    if tag_ids is not None:
        stmt = stmt.join(DeviceTag).where(DeviceTag.tag_id.in_(tag_ids))

    total_q = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(total_q)).scalar_one()
    result = await db.execute(stmt.offset(offset).limit(limit))
    devices = result.scalars().unique().all()

    # Check if ServiceNow integration is configured + get last sync time
    snow_result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.vendor == Vendor.servicenow,
            IntegrationConfig.is_enabled.is_(True),
        )
    )
    snow_integration = snow_result.scalar_one_or_none()
    last_sync_at = snow_integration.last_sync_at.isoformat() if snow_integration and snow_integration.last_sync_at else None

    return {
        "records": [_to_cmdb_record(d) for d in devices],
        "total": total,
        "last_sync_at": last_sync_at,
        "servicenow_enabled": snow_integration is not None,
    }


@router.post("/sync", status_code=202)
async def sync_to_servicenow(
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Trigger a push of CMDB records to ServiceNow.
    Runs the ServiceNow integration connector sync in the background.
    Returns immediately with 202 -- check last_sync_at to confirm completion.
    """
    from api.models.integration import IntegrationConfig, Vendor

    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.vendor == Vendor.servicenow,
            IntegrationConfig.is_enabled.is_(True),
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(422, detail="ServiceNow integration not configured")

    import asyncio
    from api.integrations import sync_by_id
    from api.core.db import _session_factory  # type: ignore[attr-defined]

    async def _run():
        try:
            async with _session_factory() as bg_db:
                await sync_by_id(bg_db, str(integration.id))
        except Exception as exc:
            log.warning("ServiceNow CMDB sync failed: %s", exc)

    asyncio.create_task(_run())
    return {"accepted": True, "message": "ServiceNow sync triggered"}


# ServiceNow CMDB CI class mapping by device type
_CI_CLASS_MAP = {
    "workstation": "cmdb_ci_computer",
    "server": "cmdb_ci_server",
    "network_device": "cmdb_ci_netgear",
    "cloud_instance": "cmdb_ci_vm_instance",
    "unknown": "cmdb_ci_hardware",
}


@router.get("/export")
async def export_cmdb(
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    tag: str | None = Query(None, description="Filter by tag name"),
    device_type: str | None = None,
    limit: int = Query(10000, le=50000),
):
    """
    Full CMDB export in ServiceNow import set format.
    Use this JSON as the source for a ServiceNow Import Set transform map.
    """
    tag_ids = await get_accessible_device_tag_ids(current_user, db)
    stmt = select(Device).options(
        selectinload(Device.owner),
        selectinload(Device.tags).selectinload(DeviceTag.tag),
    ).limit(limit)

    if tag_ids is not None:
        stmt = stmt.join(DeviceTag).where(DeviceTag.tag_id.in_(tag_ids))
    if device_type:
        stmt = stmt.where(Device.device_type == device_type)

    if tag:
        from api.models.tag import Tag
        tag_result = await db.execute(select(Tag).where(Tag.name == tag))
        t = tag_result.scalar_one_or_none()
        if t:
            stmt = stmt.join(DeviceTag, isouter=True).where(DeviceTag.tag_id == t.id)

    result = await db.execute(stmt)
    devices = result.scalars().unique().all()

    return {
        "export_time": datetime.now(timezone.utc).isoformat(),
        "schema_version": "1.0",
        "source": "open-ctem",
        "record_count": len(devices),
        "configuration_items": [_to_ci(d) for d in devices],
    }


_ENV_KEYWORDS = {"prod", "production", "staging", "stage", "dev", "development", "test", "qa", "uat", "sandbox"}

def _to_cmdb_record(d: Device) -> dict:
    """UI-facing CMDB record. IP withheld; use /export (cyber/admin) for full details."""
    owner_obj = getattr(d, "owner", None)
    owner_name = None
    if owner_obj:
        owner_name = getattr(owner_obj, "display_name", None) or getattr(owner_obj, "username", None)

    environment = None
    for dt in (d.tags or []):
        tag = getattr(dt, "tag", None)
        if tag and tag.name.lower() in _ENV_KEYWORDS:
            environment = tag.name
            break

    return {
        "id":               str(d.id),
        "hostname":         d.hostname,
        "ip_address":       None,   # encrypted at rest; not exposed in list view
        "device_type":      d.device_type.value if d.device_type else None,
        "os_name":          d.os,
        "os_version":       d.os_version,
        "owner":            owner_name,
        "environment":      environment,
        "servicenow_ci_id": None,   # populated after first ServiceNow sync
        "last_seen":        d.last_seen.isoformat() if d.last_seen else None,
        "risk_grade":       d.risk_grade.value if d.risk_grade else None,
        "source":           d.source,
    }


def _to_ci(d: Device) -> dict:
    """Full ServiceNow CI record for the JSON export."""
    return {
        "ci_id": str(d.id),
        "ci_class": _CI_CLASS_MAP.get(d.device_type.value if d.device_type else "unknown", "cmdb_ci_hardware"),
        "name": d.hostname,
        "fqdn": d.fqdn,
        "os": d.os,
        "os_version": d.os_version,
        "mac_address": d.mac_address,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "ad_joined": d.ad_joined,
        "edr_vendor": d.edr_vendor,
        "edr_active": d.edr_active,
        "is_internet_exposed": d.is_internet_exposed,
        "risk_grade": d.risk_grade.value if d.risk_grade else None,
        "risk_score": d.risk_score,
        "tags": [dt.tag.name for dt in d.tags if dt.tag],
        "device_type": d.device_type.value if d.device_type else None,
        "source": d.source,
    }
