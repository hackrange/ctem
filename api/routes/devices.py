"""Device inventory and risk API. BOLA-safe -- every object fetch verifies access."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.device_scope import device_scope
from api.auth.rbac import can_access_device, require_permission
from api.core.csv_export import csv_paged_response
from api.core.db import get_session
from api.models.device import Device, DeviceTag, DeviceType
from api.models.user import User
from api.models.vuln import Finding, FindingStatus, Vulnerability
from api.routes import device_query as dq

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])
log = logging.getLogger("open-ctem.devices")

_OPEN = (FindingStatus.open, FindingStatus.in_progress)
_FINDING_SORTS = {
    "composite_score": Finding.composite_score,
    "cvss_base": Vulnerability.cvss_base,
    "epss_score": Vulnerability.epss_score,
    "is_kev": Vulnerability.is_kev,
    "cve_id": Vulnerability.cve_id,
    "title": Vulnerability.title,
    "status": Finding.status,
    "first_detected": Finding.first_detected,
    "last_seen": Finding.last_seen,
}


async def _filtered(user, db, q, grade, device_type, source, tag):
    return dq.build_query(await device_scope(user, db), q, grade, device_type, source, tag)


_TAGS = Query(None, max_length=128, description="Tag name; repeat to require several")


@router.get("")
async def list_devices(
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    device_type: DeviceType | None = None,
    grade: str | None = Query(None, max_length=8),
    source: str | None = Query(None, max_length=64),
    tag: list[str] | None = _TAGS,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    stmt = await _filtered(current_user, db, q, grade, device_type, source, tag)
    total = (await db.execute(dq.count_query(stmt))).scalar_one()
    page = dq.with_relations(dq.sorted_query(stmt, sort, order)).limit(limit).offset(offset)
    devices = (await db.execute(page)).scalars().unique().all()
    return {"devices": [dq.summary(d) for d in devices], "total": total, "limit": limit, "offset": offset}


@router.get("/summary")
async def device_summary(
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    device_type: DeviceType | None = None,
    grade: str | None = Query(None, max_length=8),
    source: str | None = Query(None, max_length=64),
    tag: list[str] | None = _TAGS,
):
    """Dashboard counts across every device the user can see (not one page of them)."""
    stmt = await _filtered(current_user, db, q, grade, device_type, source, tag)
    grades = {g: 0 for g in ("A", "B", "C", "D", "F")}
    ungraded = kev_devices = 0
    for g, n, kev in (await db.execute(dq.grade_counts_query(stmt))).all():
        kev_devices += kev
        if g is None:
            ungraded += n
        else:
            grades[g.value if hasattr(g, "value") else str(g)] = n
    envs = [{"env": (env or "env:Unknown").removeprefix("env:"), "devices": n,
             "avg_score": round(float(avg), 1) if avg is not None else None, "critical": int(crit or 0)}
            for env, n, avg, crit in (await db.execute(dq.env_breakdown_query(stmt))).all()]
    envs.sort(key=lambda e: -e["devices"])
    return {"total": sum(grades.values()) + ungraded, "grades": grades, "ungraded": ungraded,
            "kev_devices": kev_devices, "environments": envs}


@router.get("/export")
async def export_devices(
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    device_type: DeviceType | None = None,
    grade: str | None = Query(None, max_length=8),
    source: str | None = Query(None, max_length=64),
    tag: list[str] | None = _TAGS,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
):
    stmt = dq.with_relations(dq.sorted_query(await _filtered(current_user, db, q, grade, device_type, source, tag),
                                             sort, order))

    async def fetch(offset: int, limit: int) -> list[list]:
        rows = [dq.export_row(d) for d in (await db.execute(stmt.limit(limit).offset(offset))).scalars().unique()]
        db.expunge_all()
        return rows

    resp = await csv_paged_response("devices", dq.EXPORT_HEADER, fetch)
    log.info("device export by user %s: %s rows", current_user.id, resp.headers["X-Export-Rows"])
    return resp


async def _visible_device(device_id: uuid.UUID, user, db) -> Device:
    result = await db.execute(
        select(Device).options(selectinload(Device.tags).selectinload(DeviceTag.tag), selectinload(Device.owner))
        .where(Device.id == str(device_id))
    )
    device = result.scalar_one_or_none()
    # Same 404 for "not found" and "no access" -- prevents enumeration
    if device is None or not await can_access_device(user, device, db):
        raise HTTPException(404)
    return device


@router.get("/{device_id}")
async def get_device(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
):
    device = await _visible_device(device_id, current_user, db)
    base = dq.summary(device)
    base.update({
        "fqdn": dq.full_name(device),
        "mac_address": device.mac_address,
        "os_version": device.os_version,
        "ad_last_logon": device.ad_last_logon.isoformat() if device.ad_last_logon else None,
        "edr_last_seen": device.edr_last_seen.isoformat() if device.edr_last_seen else None,
        "last_login_user": device.last_login_user,
    })
    return base


def _findings_query(device_id: str, status: str | None, q: str | None):
    stmt = select(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(Finding.device_id == device_id)
    if status in (None, "", "active"):
        stmt = stmt.where(Finding.status.in_(_OPEN))
    elif status != "all":
        stmt = stmt.where(Finding.status == FindingStatus(status))
    if q:
        like = dq._like(q.strip()[:200])
        stmt = stmt.where(or_(Vulnerability.cve_id.ilike(like, escape="\\"), Vulnerability.title.ilike(like, escape="\\")))
    return stmt


def _sorted_findings(stmt, sort, order):
    col = _FINDING_SORTS.get(sort or "", Vulnerability.cvss_base)
    direction = col.asc() if (order or "").lower() == "asc" else col.desc()
    return stmt.order_by(direction.nullslast(), Vulnerability.title.asc(), Finding.id.asc()).options(selectinload(Finding.vuln))


_STATUS_PATTERN = "^(active|all|" + "|".join(s.value for s in FindingStatus) + ")$"


@router.get("/{device_id}/findings")
async def get_device_findings(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    q: str | None = Query(None, max_length=200),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    device = await _visible_device(device_id, current_user, db)
    stmt = _findings_query(device.id, status, q)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(_sorted_findings(stmt, sort, order).limit(limit).offset(offset))).scalars().all()
    return {"findings": [_finding_summary(f) for f in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/{device_id}/findings/export")
async def export_device_findings(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    q: str | None = Query(None, max_length=200),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
):
    device = await _visible_device(device_id, current_user, db)
    hostname = device.hostname
    stmt = _sorted_findings(_findings_query(device.id, status, q), sort, order)
    header = ["Hostname", "CVE", "Title", "CVSS", "EPSS", "KEV", "Score", "Status", "First detected", "Last seen", "Source"]

    async def fetch(offset: int, limit: int) -> list[list]:
        rows = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
        out = [[hostname, f.vuln.cve_id, f.vuln.title, f.vuln.cvss_base, f.vuln.epss_score, f.vuln.is_kev,
                f.composite_score, f.status.value, _iso(f.first_detected), _iso(f.last_seen), f.source] for f in rows]
        db.expunge_all()
        return out

    return await csv_paged_response(f"findings-{hostname}", header, fetch)


def _iso(dt):
    return dt.isoformat() if dt else None


def _finding_summary(f: Finding) -> dict:
    v = f.vuln
    return {
        "id": str(f.id),
        "vuln_id": str(f.vuln_id),
        "cve_id": v.cve_id if v else None,
        "title": v.title if v else None,
        "cvss_base": v.cvss_base if v else None,
        "epss_score": v.epss_score if v else None,
        "is_kev": v.is_kev if v else False,
        "composite_score": f.composite_score,
        "risk_grade": f.risk_grade,
        "status": f.status.value,
        "source": f.source,
        "is_reachable": f.is_reachable,
        "reachability_source": f.reachability_source,
        "in_attack_chain": f.in_attack_chain,
        "first_detected": _iso(f.first_detected),
        "last_seen": _iso(f.last_seen),
    }
