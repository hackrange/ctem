"""CMDB JSON export endpoint for ServiceNow import sets."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import get_accessible_device_tag_ids, require_cyber_or_admin
from api.core.db import get_session
from api.models.device import Device, DeviceTag
from api.models.user import User

router = APIRouter(prefix="/api/v1/cmdb", tags=["cmdb"])

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
    stmt = select(Device).options(selectinload(Device.tags)).limit(limit)

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


def _to_ci(d: Device) -> dict:
    return {
        "ci_id": str(d.id),
        "ci_class": _CI_CLASS_MAP.get(d.device_type.value, "cmdb_ci_hardware"),
        "name": d.hostname,
        "fqdn": d.fqdn,
        "os": d.os,
        "os_version": d.os_version,
        "mac_address": d.mac_address,
        # IP is decrypted here -- this endpoint requires cyber/admin
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "ad_joined": d.ad_joined,
        "edr_vendor": d.edr_vendor,
        "edr_active": d.edr_active,
        "is_internet_exposed": d.is_internet_exposed,
        "risk_grade": d.risk_grade.value if d.risk_grade else None,
        "risk_score": d.risk_score,
        "tags": [dt.tag.name for dt in d.tags if dt.tag],
        "device_type": d.device_type.value,
        "source": d.source,
    }
