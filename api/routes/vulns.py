"""Vulnerability inventory and finding management."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.user import User
from api.models.vuln import Finding, FindingStatus, Vulnerability

router = APIRouter(prefix="/api/v1/vulns", tags=["vulns"])


@router.get("")
async def list_vulns(
    _: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    is_kev: bool | None = None,
    min_cvss: float | None = None,
    cve_id: str | None = None,
    limit: int = Query(50, le=200),
    cursor: str | None = None,
):
    stmt = select(Vulnerability).order_by(Vulnerability.cvss_base.desc().nullslast())
    if is_kev is not None:
        stmt = stmt.where(Vulnerability.is_kev == is_kev)
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_base >= min_cvss)
    if cve_id:
        stmt = stmt.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
    if cursor:
        stmt = stmt.where(Vulnerability.id < uuid.UUID(cursor))
    stmt = stmt.limit(limit + 1)

    result = await db.execute(stmt)
    vulns = result.scalars().all()
    next_cursor = str(vulns[-1].id) if len(vulns) > limit else None

    # Enrich with affected device count
    ids = [v.id for v in vulns[:limit]]
    if ids:
        counts_result = await db.execute(
            select(Finding.vuln_id, func.count(Finding.device_id).label("cnt"))
            .where(Finding.vuln_id.in_(ids), Finding.status == FindingStatus.open)
            .group_by(Finding.vuln_id)
        )
        counts = {r.vuln_id: r.cnt for r in counts_result}
    else:
        counts = {}

    return {
        "vulns": [_vuln_summary(v, counts.get(v.id, 0)) for v in vulns[:limit]],
        "next_cursor": next_cursor,
    }


@router.get("/{vuln_id}/findings")
async def list_vuln_findings(
    vuln_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    status: FindingStatus | None = None,
    limit: int = Query(50, le=200),
):
    """Open findings for a specific vulnerability, filtered to devices this user can access."""
    from api.auth.rbac import get_accessible_device_tag_ids
    from api.models.device import Device, DeviceTag

    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(404)

    stmt = (
        select(Finding)
        .options(selectinload(Finding.device))
        .where(Finding.vuln_id == vuln_id)
    )
    if status:
        stmt = stmt.where(Finding.status == status)
    else:
        stmt = stmt.where(Finding.status == FindingStatus.open)

    stmt = stmt.limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    # Filter to devices the caller is allowed to see (None = unrestricted)
    accessible = await get_accessible_device_tag_ids(current_user, db)
    visible = []
    for f in rows:
        dev = f.device
        if accessible is None:   # admin / cyber -- see everything
            visible.append(f)
            continue
        if not dev.tags:         # untagged device -- visible to restricted roles too
            visible.append(f)
            continue
        dev_tag_ids = {dt.tag_id for dt in dev.tags}
        if dev_tag_ids & set(accessible):
            visible.append(f)

    return {
        "findings": [
            {
                "id":              str(f.id),
                "device_id":       str(f.device_id),
                "hostname":        f.device.hostname if f.device else None,
                "status":          f.status.value,
                "composite_score": f.composite_score,
                "risk_grade":      f.risk_grade,
                "is_reachable":    f.is_reachable,
                "first_detected":  f.first_detected.isoformat() if f.first_detected else None,
                "last_seen":       f.last_seen.isoformat() if f.last_seen else None,
            }
            for f in visible
        ],
        "total": len(visible),
    }


@router.get("/{vuln_id}")
async def get_vuln(
    vuln_id: uuid.UUID,
    _: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if vuln is None:
        raise HTTPException(404)
    return _vuln_summary(vuln, 0)


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: uuid.UUID,
    body: UpdateFindingStatusRequest,
    current_user: User = Depends(require_permission("findings", "write")),
    db: AsyncSession = Depends(get_session),
):
    """Update finding status (accept risk, remediate, false positive)."""
    from api.auth.rbac import can_access_device
    from api.models.device import Device

    result = await db.execute(
        select(Finding).options(selectinload(Finding.device)).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(404)

    # Object-level auth -- user must be able to see the device this finding is on
    if not await can_access_device(current_user, finding.device, db):
        raise HTTPException(404)

    finding.status = body.status
    if body.note:
        finding.status_note = body.note
    finding.status_updated_at = __import__("datetime").datetime.utcnow()
    await db.commit()
    return {"updated": True}


def _vuln_summary(v: Vulnerability, affected_devices: int) -> dict:
    return {
        "id": str(v.id),
        "cve_id": v.cve_id,
        "title": v.title,
        "description": v.description,
        "cvss_base": v.cvss_base,
        "cvss_vector": v.cvss_vector,
        "epss_score": v.epss_score,
        "is_kev": v.is_kev,
        "kev_added_date": v.kev_added_date.isoformat() if v.kev_added_date else None,
        "attack_vector": v.attack_vector,
        "published_date": v.published_date.isoformat() if v.published_date else None,
        "mitre_technique": v.mitre_technique,
        "affected_devices": affected_devices,
    }


class UpdateFindingStatusRequest(BaseModel):
    status: FindingStatus
    note: str | None = None
