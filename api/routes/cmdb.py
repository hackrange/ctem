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
from api.models.device import Device, DeviceTag, DeviceType
from api.models.user import User
from api.routes.device_query import environment, full_name, short_name, source_codes, user_label

log = logging.getLogger("open-ctem.cmdb")
router = APIRouter(prefix="/api/v1/cmdb", tags=["cmdb"])

_SORTS = {"hostname": Device.host_key, "device_type": Device.device_type, "os": Device.os,
          "last_seen": Device.last_seen, "risk_grade": Device.risk_grade}


def _scoped(stmt, tag_ids):
    # IN (subquery) rather than a join: a device with two visible tags must count once
    if tag_ids is None:
        return stmt
    return stmt.where(Device.id.in_(select(DeviceTag.device_id).where(DeviceTag.tag_id.in_(tag_ids))))


@router.get("")
async def list_cmdb(
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    device_type: DeviceType | None = None,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    """CMDB record list for the UI table (server-side paged), with ServiceNow integration status."""
    from sqlalchemy import func, or_

    from api.models.integration import IntegrationConfig, Vendor
    from api.routes.device_query import _like

    tag_ids = await get_accessible_device_tag_ids(current_user, db)
    stmt = _scoped(select(Device), tag_ids)
    if device_type:
        stmt = stmt.where(Device.device_type == device_type)
    if q and q.strip():
        like = _like(q.strip()[:200])
        stmt = stmt.where(or_(Device.hostname.ilike(like, escape="\\"), Device.fqdn.ilike(like, escape="\\"),
                              Device.os.ilike(like, escape="\\")))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    col = _SORTS.get(sort or "", Device.host_key)
    ordered = col.desc().nulls_last() if order == "desc" else col.asc().nulls_last()
    # Named hosts first; bare-IP scanner assets (no FQDN, often no OS) sink to the end
    # host_key keeps dots only for IP literals, so this flags bare-IP assets portably
    is_ip = or_(Device.host_key.like("%.%"), Device.host_key.like("%:%"))
    named_first = is_ip if col is Device.host_key else None
    keys = [k for k in (named_first, ordered, Device.id) if k is not None]
    page = (stmt.options(selectinload(Device.owner), selectinload(Device.tags).selectinload(DeviceTag.tag))
            .order_by(*keys).offset(offset).limit(limit))
    devices = (await db.execute(page)).scalars().unique().all()

    snow = (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.vendor == Vendor.servicenow, IntegrationConfig.is_enabled.is_(True)))).scalar_one_or_none()
    return {
        "records": [_to_cmdb_record(d) for d in devices],
        "total": total,
        "limit": limit,
        "offset": offset,
        "last_sync_at": snow.last_sync_at.isoformat() if snow and snow.last_sync_at else None,
        "servicenow_enabled": snow is not None,
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
    device_type: DeviceType | None = None,
    limit: int = Query(200_000, ge=1, le=200_000),
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

    stmt = _scoped(stmt, tag_ids)
    if device_type:
        stmt = stmt.where(Device.device_type == device_type)

    if tag:
        from api.models.tag import Tag
        tag_result = await db.execute(select(Tag).where(Tag.name == tag))
        t = tag_result.scalar_one_or_none()
        if t:
            stmt = stmt.where(Device.id.in_(select(DeviceTag.device_id).where(DeviceTag.tag_id == t.id)))

    result = await db.execute(stmt)
    devices = result.scalars().unique().all()

    return {
        "export_time": datetime.now(timezone.utc).isoformat(),
        "schema_version": "1.0",
        "source": "open-ctem",
        "record_count": len(devices),
        "configuration_items": [_to_ci(d) for d in devices],
    }



def _to_cmdb_record(d: Device) -> dict:
    """UI-facing CMDB record. IP withheld; use /export (cyber/admin) for full details."""

    return {
        "id":               str(d.id),
        "hostname":         short_name(d.hostname),
        "fqdn":             full_name(d),
        "ip_address":       None,   # encrypted at rest; not exposed in list view
        "device_type":      d.device_type.value if d.device_type else None,
        "os_name":          d.os,
        "os_version":       d.os_version,
        "owner":            user_label(d),
        "environment":      environment(d),
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
        "name": short_name(d.hostname),
        "fqdn": full_name(d),
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
        "sources": source_codes(d),
        "owner": user_label(d),
        "environment": environment(d),
        "firewall_enabled": d.firewall_enabled,
        "usb_storage_blocked": d.usb_storage_blocked,
    }
