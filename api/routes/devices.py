"""Device inventory and risk API. BOLA-safe -- every object fetch verifies access."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import can_access_device, get_accessible_device_tag_ids, require_permission
from api.core.db import get_session
from api.models.device import Device, DeviceTag, DeviceType
from api.models.user import User
from api.models.vuln import Finding, FindingStatus

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


@router.get("")
async def list_devices(
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    device_type: DeviceType | None = None,
    grade: str | None = None,
    tag: str | None = None,
    cursor: str | None = None,
    limit: int = Query(50, le=200),
):
    tag_ids = await get_accessible_device_tag_ids(current_user, db)

    stmt = (
        select(Device)
        .options(selectinload(Device.tags))
        .order_by(Device.risk_score.desc().nullslast())
    )

    if tag_ids is not None:
        # Restrict to devices the user's tag assignments cover
        stmt = stmt.join(DeviceTag).where(DeviceTag.tag_id.in_(tag_ids))

    if device_type:
        stmt = stmt.where(Device.device_type == device_type)
    if grade:
        stmt = stmt.where(Device.risk_grade == grade.upper())
    if tag:
        from api.models.tag import Tag
        tag_result = await db.execute(select(Tag).where(Tag.name == tag))
        t = tag_result.scalar_one_or_none()
        if t:
            stmt = stmt.join(DeviceTag, isouter=True).where(DeviceTag.tag_id == t.id)
    if cursor:
        stmt = stmt.where(Device.id < str(cursor))

    stmt = stmt.limit(limit + 1)
    result = await db.execute(stmt)
    devices = result.scalars().unique().all()
    next_cursor = str(devices[-1].id) if len(devices) > limit else None

    return {
        "devices": [_device_summary(d) for d in devices[:limit]],
        "next_cursor": next_cursor,
    }


@router.get("/{device_id}")
async def get_device(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Device).options(selectinload(Device.tags)).where(Device.id == str(device_id))
    )
    device = result.scalar_one_or_none()
    # Return 404 for both "not found" and "no access" -- prevents enumeration
    if device is None or not await can_access_device(current_user, device, db):
        raise HTTPException(404)
    return _device_detail(device)


@router.get("/{device_id}/findings")
async def get_device_findings(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    status: FindingStatus | None = None,
):
    # Object-level auth first
    device_result = await db.execute(
        select(Device).options(selectinload(Device.tags)).where(Device.id == str(device_id))
    )
    device = device_result.scalar_one_or_none()
    if device is None or not await can_access_device(current_user, device, db):
        raise HTTPException(404)

    stmt = (
        select(Finding)
        .options(selectinload(Finding.vuln))
        .where(Finding.device_id == str(device_id))
        .order_by(Finding.composite_score.desc().nullslast())
    )
    if status:
        stmt = stmt.where(Finding.status == status)

    result = await db.execute(stmt)
    findings = result.scalars().all()
    return {"findings": [_finding_summary(f) for f in findings]}


# ── Serializers ───────────────────────────────────────────────────────────────

def _device_summary(d: Device) -> dict:
    return {
        "id": str(d.id),
        "hostname": d.hostname,
        "os": d.os,
        "device_type": d.device_type.value,
        "risk_score": d.risk_score,
        "risk_grade": d.risk_grade.value if d.risk_grade else None,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "edr_active": d.edr_active,
        "edr_vendor": d.edr_vendor,
        "ad_joined": d.ad_joined,
        "is_internet_exposed": d.is_internet_exposed,
        "tags": [dt.tag.name for dt in d.tags if dt.tag],
    }


def _device_detail(d: Device) -> dict:
    base = _device_summary(d)
    base.update({
        "fqdn": d.fqdn,
        "mac_address": d.mac_address,
        "os_version": d.os_version,
        "ad_last_logon": d.ad_last_logon.isoformat() if d.ad_last_logon else None,
        "edr_last_seen": d.edr_last_seen.isoformat() if d.edr_last_seen else None,
    })
    return base


def _finding_summary(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "cve_id": f.vuln.cve_id if f.vuln else None,
        "title": f.vuln.title if f.vuln else None,
        "cvss_base": f.vuln.cvss_base if f.vuln else None,
        "epss_score": f.vuln.epss_score if f.vuln else None,
        "is_kev": f.vuln.is_kev if f.vuln else False,
        "composite_score": f.composite_score,
        "risk_grade": f.risk_grade,
        "status": f.status.value,
        "is_reachable": f.is_reachable,
        "reachability_source": f.reachability_source,
        "in_attack_chain": f.in_attack_chain,
        "first_detected": f.first_detected.isoformat() if f.first_detected else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
    }
