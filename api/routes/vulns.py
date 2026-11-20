"""Vulnerability inventory, affected devices, and finding management."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.device_scope import device_scope
from api.auth.rbac import require_permission
from api.core.csv_export import csv_paged_response
from api.core.db import get_session
from api.models.device import Device, DeviceAssignment, DeviceTag
from api.models.user import User
from api.models.vuln import Finding, FindingStatus, Vulnerability
from api.routes import device_query as dq

router = APIRouter(prefix="/api/v1/vulns", tags=["vulns"])
log = logging.getLogger("open-ctem.vulns")

_OPEN = (FindingStatus.open, FindingStatus.in_progress)
_STATUS_PATTERN = "^(active|all|" + "|".join(s.value for s in FindingStatus) + ")$"


def _affected_count(scope):
    """Correlated count of distinct visible devices with an active finding for this vuln."""
    stmt = (select(func.count(distinct(Finding.device_id)))
            .join(Device, Device.id == Finding.device_id)
            .where(Finding.vuln_id == Vulnerability.id, Finding.status.in_(_OPEN)))
    if scope is not None:
        stmt = stmt.where(scope)
    return stmt.correlate(Vulnerability).scalar_subquery()


def _vuln_query(scope, q, is_kev, min_cvss, source, affected_only):
    # Global roles read the stored count; tag-scoped users get a live count of only their devices
    affected = (Vulnerability.affected_devices if scope is None else _affected_count(scope)).label("affected")
    stmt = select(Vulnerability, affected)
    if q:
        like = dq._like(q.strip()[:200])  # partial, case-insensitive match
        stmt = stmt.where(or_(
            Vulnerability.cve_id.ilike(like, escape="\\"),
            Vulnerability.title.ilike(like, escape="\\"),
            Vulnerability.source_vuln_id.ilike(like, escape="\\"),
        ))
    if is_kev is not None:
        stmt = stmt.where(Vulnerability.is_kev == is_kev)
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_base >= min_cvss)
    if source:
        stmt = stmt.where(Vulnerability.source == source[:64])
    if affected_only:
        stmt = stmt.where((Vulnerability.affected_devices if scope is None else _affected_count(scope)) > 0)
    return stmt, affected


def _vuln_sorts(affected):
    return {
        "cve_id": Vulnerability.cve_id,
        "title": Vulnerability.title,
        "cvss_base": Vulnerability.cvss_base,
        "epss_score": Vulnerability.epss_score,
        "is_kev": Vulnerability.is_kev,
        "exploit_available": Vulnerability.exploit_available,
        "source": Vulnerability.source,
        "affected": affected,
    }


def _sorted_vulns(stmt, affected, sort, order):
    col = _vuln_sorts(affected).get(sort or "", Vulnerability.cvss_base)
    direction = col.asc() if (order or "").lower() == "asc" else col.desc()
    return stmt.order_by(direction.nullslast(), Vulnerability.title.asc(), Vulnerability.id.asc())


@router.get("")
async def list_vulns(
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    cve_id: str | None = Query(None, max_length=200),  # older callers; same as q
    is_kev: bool | None = None,
    min_cvss: float | None = Query(None, ge=0, le=10),
    source: str | None = Query(None, max_length=64),
    affected_only: bool = False,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    scope = await device_scope(current_user, db)
    stmt, affected = _vuln_query(scope, q or cve_id, is_kev, min_cvss, source, affected_only)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(_sorted_vulns(stmt, affected, sort, order).limit(limit).offset(offset))).all()
    return {"vulns": [_vuln_summary(v, n) for v, n in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/export")
async def export_vulns(
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    is_kev: bool | None = None,
    min_cvss: float | None = Query(None, ge=0, le=10),
    source: str | None = Query(None, max_length=64),
    affected_only: bool = False,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
):
    scope = await device_scope(current_user, db)
    stmt, affected = _vuln_query(scope, q, is_kev, min_cvss, source, affected_only)
    stmt = _sorted_vulns(stmt, affected, sort, order)
    header = ["CVE", "Title", "CVSS", "EPSS", "KEV", "KEV added", "Exploit available", "Affected devices",
              "Source", "Source ID"]

    async def fetch(offset: int, limit: int) -> list[list]:
        rows = (await db.execute(stmt.limit(limit).offset(offset))).all()
        out = [[v.cve_id, v.title, v.cvss_base, v.epss_score, v.is_kev, v.kev_added_date, v.exploit_available, n,
                v.source, v.source_vuln_id] for v, n in rows]
        db.expunge_all()
        return out

    resp = await csv_paged_response("vulnerabilities", header, fetch)
    log.info("vuln export by user %s: %s rows", current_user.id, resp.headers["X-Export-Rows"])
    return resp


_AFFECTED_SORTS = {
    "hostname": Device.hostname,
    "user": dq.Owner.username,
    "os": Device.os,
    "risk_grade": Device.risk_grade,
    "risk_score": Device.risk_score,
    "status": Finding.status,
    "first_detected": Finding.first_detected,
    "last_seen": Finding.last_seen,
}


def _affected_query(vuln_id: str, scope, status, q):
    stmt = (select(Finding).join(Device, Device.id == Finding.device_id)
            .outerjoin(dq.Owner, dq.Owner.id == Device.owner_user_id)
            .where(Finding.vuln_id == vuln_id))
    if scope is not None:
        stmt = stmt.where(scope)
    if status in (None, "", "active"):
        stmt = stmt.where(Finding.status.in_(_OPEN))
    elif status != "all":
        stmt = stmt.where(Finding.status == FindingStatus(status))
    if q:
        like = dq._like(q.strip()[:200])
        stmt = stmt.where(or_(Device.hostname.ilike(like, escape="\\"), dq.Owner.username.ilike(like, escape="\\")))
    return stmt


def _sorted_affected(stmt, sort, order):
    col = _AFFECTED_SORTS.get(sort or "", Device.risk_score)
    direction = col.asc() if (order or "").lower() == "asc" else col.desc()
    return stmt.order_by(direction.nullslast(), Device.hostname.asc(), Finding.id.asc()).options(
        selectinload(Finding.device).selectinload(Device.owner),
        selectinload(Finding.device).selectinload(Device.assignment).selectinload(DeviceAssignment.user),
        selectinload(Finding.device).selectinload(Device.tags).selectinload(DeviceTag.tag),
    )


async def _vuln_or_404(vuln_id: uuid.UUID, db) -> Vulnerability:
    vuln = (await db.execute(select(Vulnerability).where(Vulnerability.id == str(vuln_id)))).scalar_one_or_none()
    if vuln is None:
        raise HTTPException(404)
    return vuln


@router.get("/{vuln_id}/findings")
async def list_vuln_findings(
    vuln_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    q: str | None = Query(None, max_length=200),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    """Devices affected by a vulnerability, limited in SQL to devices this user can access."""
    vuln = await _vuln_or_404(vuln_id, db)
    stmt = _affected_query(str(vuln_id), await device_scope(current_user, db), status, q)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(_sorted_affected(stmt, sort, order).limit(limit).offset(offset))).scalars().all()
    return {"findings": [_affected_row(f, vuln.cvss_base) for f in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/{vuln_id}/findings/export")
async def export_vuln_findings(
    vuln_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    q: str | None = Query(None, max_length=200),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
):
    vuln = await _vuln_or_404(vuln_id, db)
    cve, title, name = vuln.cve_id, vuln.title, f"affected-{vuln.cve_id or vuln.id}"
    stmt = _sorted_affected(_affected_query(str(vuln_id), await device_scope(current_user, db), status, q), sort, order)
    header = ["CVE", "Title", "Hostname", "User", "IP", "OS", "Grade", "Device score", "Status",
              "First detected", "Last seen"]

    async def fetch(offset: int, limit: int) -> list[list]:
        out = []
        for f in (await db.execute(stmt.limit(limit).offset(offset))).scalars().all():
            r = _affected_row(f, vuln.cvss_base)
            out.append([cve, title, r["hostname"], r["user"], r["ip"], r["os"], r["device_grade"],
                        r["device_score"], r["status"], r["first_detected"], r["last_seen"]])
        db.expunge_all()
        return out

    return await csv_paged_response(name, header, fetch)


@router.get("/{vuln_id}")
async def get_vuln(
    vuln_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
):
    vuln = await _vuln_or_404(vuln_id, db)
    affected = _affected_count(await device_scope(current_user, db))
    n = (await db.execute(select(affected).select_from(Vulnerability).where(Vulnerability.id == vuln.id))).scalar_one()
    out = _vuln_summary(vuln, n)
    out.update({"source_vuln_id": vuln.source_vuln_id, "exploit_maturity": vuln.exploit_maturity,
                "epss_updated_at": vuln.epss_updated_at.isoformat() if vuln.epss_updated_at else None})
    return out


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
        select(Finding)
        .options(selectinload(Finding.device).selectinload(Device.tags))
        .where(Finding.id == str(finding_id))
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


def _iso(dt):
    return dt.isoformat() if dt else None


def _affected_row(f: Finding, cvss: float | None = None) -> dict:
    d = f.device
    return {
        "id": str(f.id),
        "device_id": str(f.device_id),
        "hostname": dq.short_name(d.hostname) if d else None,
        "contained": bool(d.edr_contained) if d else False,
        "severity": dq.severity(cvss, bool(d and d.edr_contained)),
        "user": dq.user_label(d) if d else None,
        "ip": d.ip if d else None,
        "os": d.os if d else None,
        "device_grade": d.risk_grade.value if d and d.risk_grade else None,
        "device_score": d.risk_score if d else None,
        "raw_device_grade": d.raw_risk_grade if d else None,
        "raw_device_score": d.raw_risk_score if d else None,
        "status": f.status.value,
        "composite_score": f.composite_score,
        "risk_grade": f.risk_grade,
        "is_reachable": f.is_reachable,
        "first_detected": _iso(f.first_detected),
        "last_seen": _iso(f.last_seen),
    }


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
        "exploit_available": v.exploit_available,
        "source": v.source,
        "affected_devices": affected_devices or 0,
    }


class UpdateFindingStatusRequest(BaseModel):
    status: FindingStatus
    note: str | None = None
