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
from api.core.device_scope_exempt import in_scope, is_exempt
from api.models.device import Device, DeviceAssignment, DeviceTag
from api.models.user import User
from api.core import cloud_findings, sla
from api.core import finding_age as age
from api.models.vuln import Finding, FindingStatus, Vulnerability
from api.routes import device_query as dq
from api.scoring.compensating import reach_view

router = APIRouter(prefix="/api/v1/vulns", tags=["vulns"])
log = logging.getLogger("open-ctem.vulns")

_OPEN = (FindingStatus.open, FindingStatus.in_progress)
_TAGS = Query(None, max_length=10, description="Tag name; repeat to require several (a dashboard tag focus)")
_STATUS_PATTERN = "^(active|all|" + "|".join(s.value for s in FindingStatus) + ")$"


def _affected_count(scope):
    """Correlated count of distinct visible devices with an active finding for this vuln."""
    stmt = (select(func.count(distinct(Finding.device_id)))
            .join(Device, Device.id == Finding.device_id)
            .where(Finding.vuln_id == Vulnerability.id, Finding.status.in_(_OPEN), in_scope()))
    if scope is not None:
        stmt = stmt.where(scope)
    return stmt.correlate(Vulnerability).scalar_subquery()


def _oldest(scope):
    """When this person's oldest open finding of the vuln was first found (live, for tag-scoped users)."""
    stmt = (select(func.min(Finding.first_detected)).join(Device, Device.id == Finding.device_id)
            .where(Finding.vuln_id == Vulnerability.id, Finding.status.in_(_OPEN), in_scope()))
    if scope is not None:
        stmt = stmt.where(scope)
    return stmt.correlate(Vulnerability).scalar_subquery()


def _PLACE():   # one per parameter: FastAPI binds a shared Query object to the first name it sees
    return Query(None, max_length=128, pattern=r"^[^\x00-\x1f<>]+$")


def _where(loc_state: str | None = _PLACE(), loc_city: str | None = _PLACE(), loc_site: str | None = _PLACE(),
           loc_office: str | None = _PLACE()) -> dict:
    """Only vulnerabilities on assets in this place (api/core/location.py)."""
    return {"loc_state": loc_state, "loc_city": loc_city, "loc_site": loc_site, "loc_office": loc_office}


_AGE = Query(None, ge=0, le=36500, description="Only vulnerabilities whose oldest open finding is at least this many days old")
_TYPE = Query(None, alias="type", pattern="^(infra|code|web|cloud)$", description="Infrastructure, Code, Web apps or Cloud; none = all")


def _vuln_query(scope, q, is_kev, min_cvss, source, affected_only, vtype=None, min_age_days=None, exploited=None, past_sla=False):
    # Global roles read the stored count and age; tag-scoped users get live ones for only their devices
    affected = (Vulnerability.affected_devices if scope is None else _affected_count(scope)).label("affected")
    oldest_expr = Vulnerability.first_found if scope is None else _oldest(scope)
    oldest = oldest_expr.label("oldest")
    stmt = select(Vulnerability, affected, oldest)
    if min_age_days is not None:
        from datetime import datetime, timedelta, timezone
        stmt = stmt.where(oldest_expr <= datetime.now(timezone.utc) - timedelta(days=min_age_days))
    if q:
        like = dq._like(q.strip()[:200])  # partial, case-insensitive match
        stmt = stmt.where(or_(
            Vulnerability.cve_id.ilike(like, escape="\\"),
            Vulnerability.title.ilike(like, escape="\\"),
            Vulnerability.source_vuln_id.ilike(like, escape="\\"),
        ))
    if is_kev is not None:
        stmt = stmt.where(Vulnerability.is_kev == is_kev)
    if exploited is not None:   # an autonomous pentest exploited it here, on a finding still open
        stmt = stmt.where(Vulnerability.pentest_exploited == exploited)
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_base >= min_cvss)
    if source:
        stmt = stmt.where(Vulnerability.source == source[:64])
    if vtype:
        stmt = stmt.where(Vulnerability.domain == vtype)
    if affected_only:
        stmt = stmt.where((Vulnerability.affected_devices if scope is None else _affected_count(scope)) > 0)
    if past_sla:   # an open finding older than its severity's SLA (the Security Overview's "past SLA" rows)
        from api.dashboards.m_posture import _past_sla
        late = select(Finding.id).join(Device, Device.id == Finding.device_id).where(
            Finding.vuln_id == Vulnerability.id, Finding.status.in_(_OPEN), in_scope(), _past_sla(), *([scope] if scope is not None else []))
        stmt = stmt.where(late.correlate(Vulnerability).exists())
    return stmt, (affected, oldest)


def _vuln_sorts(affected):
    return {
        "cve_id": Vulnerability.cve_id,
        "title": Vulnerability.title,
        "cvss_base": Vulnerability.cvss_base,
        "epss_score": Vulnerability.epss_score,
        "is_kev": Vulnerability.is_kev,
        "exploit_available": Vulnerability.exploit_available,
        "pentest_exploited": Vulnerability.pentest_exploited,
        "source": Vulnerability.source,
        "affected": affected,
    }


def _sorted_vulns(stmt, cols, sort, order):
    affected, oldest = cols
    asc = (order or "").lower() == "asc"
    if sort == "age":   # oldest first is the highest age
        col, asc = oldest, not asc
    else:
        col = _vuln_sorts(affected).get(sort or "", Vulnerability.cvss_base)
    direction = col.asc() if asc else col.desc()
    then = [Vulnerability.cvss_base.desc().nullslast()] if sort in ("pentest_exploited", "is_kev", "exploit_available") else []
    return stmt.order_by(direction.nullslast(), *then, Vulnerability.title.asc(), Vulnerability.id.asc())


@router.get("")
async def list_vulns(
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    cve_id: str | None = Query(None, max_length=200),  # older callers; same as q
    is_kev: bool | None = None,
    exploited: bool | None = None,
    min_cvss: float | None = Query(None, ge=0, le=10),
    source: str | None = Query(None, max_length=64),
    affected_only: bool = False,
    tag: list[str] | None = _TAGS,
    vtype: str | None = _TYPE,
    min_age_days: int | None = _AGE,
    past_sla: bool = False,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000_000),
    where: dict = Depends(_where),
    _sla: None = Depends(sla.fresh),
):
    scope = dq.with_location(dq.with_tags(await device_scope(current_user, db), tag), where)
    # People who see only some assets see only vulnerabilities on at least one of them: the catalog of everything
    # else would open onto empty affected lists
    affected_only = affected_only or scope is not None
    stmt, cols = _vuln_query(scope, q or cve_id, is_kev, min_cvss, source, affected_only, vtype, min_age_days, exploited, past_sla)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(_sorted_vulns(stmt, cols, sort, order).limit(limit).offset(offset))).all()
    return {"vulns": [_vuln_summary(v, n, old) for v, n, old in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/export")
async def export_vulns(
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    is_kev: bool | None = None,
    exploited: bool | None = None,
    min_cvss: float | None = Query(None, ge=0, le=10),
    source: str | None = Query(None, max_length=64),
    affected_only: bool = False,
    tag: list[str] | None = _TAGS,
    vtype: str | None = _TYPE,
    min_age_days: int | None = _AGE,
    past_sla: bool = False,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    where: dict = Depends(_where),
    _sla: None = Depends(sla.fresh),
):
    scope = dq.with_location(dq.with_tags(await device_scope(current_user, db), tag), where)
    affected_only = affected_only or scope is not None
    stmt, cols = _vuln_query(scope, q, is_kev, min_cvss, source, affected_only, vtype, min_age_days, exploited, past_sla)
    stmt = _sorted_vulns(stmt, cols, sort, order)
    header = ["CVE", "Title", "Type", "CVSS", "EPSS", "KEV", "KEV added", "Exploit available", "Affected",
              "First found", "Age (days)", "Past SLA", "Source", "Source ID"]

    async def fetch(offset: int, limit: int) -> list[list]:
        rows = (await db.execute(stmt.limit(limit).offset(offset))).all()
        out = []
        for v, n, old in rows:
            a = age.view(old, None, "open", v.cvss_base)
            out.append([v.cve_id, v.title, {"infra": "Infrastructure", "code": "Code", "web": "Web app", "cloud": "Cloud"}.get(v.domain, v.domain),
                        v.cvss_base, v.epss_score, v.is_kev, v.kev_added_date, v.exploit_available, n,
                        _iso(old), a["age_days"], a["past_sla"], v.source, v.source_vuln_id])
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
    asc = (order or "").lower() == "asc"
    if sort == "age":   # oldest first is the highest age
        col, asc = Finding.first_detected, not asc
    else:
        col = _AFFECTED_SORTS.get(sort or "", Device.risk_score)
    direction = col.asc() if asc else col.desc()
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
    tag: list[str] | None = _TAGS,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    _sla: None = Depends(sla.fresh),
):
    """Devices affected by a vulnerability, limited in SQL to devices this user can access."""
    vuln = await _vuln_or_404(vuln_id, db)
    stmt = _affected_query(str(vuln_id), dq.with_tags(await device_scope(current_user, db), tag), status, q)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(_sorted_affected(stmt, sort, order).limit(limit).offset(offset))).scalars().all()
    cloud = await _cloud_ports(db, {str(f.device_id) for f in rows})
    out = [_affected_row(f, vuln.cvss_base, vuln.attack_vector, cloud.get(str(f.device_id))) for f in rows]
    await cloud_findings.with_fixes(db, list(zip(out, [f.fix_key for f in rows])))
    from api.integrations.pentest_merge import found_by
    await found_by(db, [(o, o["device_id"], vuln.cve_id) for o in out])   # one line per CVE, every tool that found it
    return {"findings": out, "total": total, "limit": limit, "offset": offset}


@router.get("/{vuln_id}/findings/export")
async def export_vuln_findings(
    vuln_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    q: str | None = Query(None, max_length=200),
    tag: list[str] | None = _TAGS,
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    _sla: None = Depends(sla.fresh),
):
    vuln = await _vuln_or_404(vuln_id, db)
    cve, title, name = vuln.cve_id, vuln.title, f"affected-{vuln.cve_id or vuln.id}"
    stmt = _sorted_affected(_affected_query(str(vuln_id), dq.with_tags(await device_scope(current_user, db), tag), status, q),
                            sort, order)
    header = ["CVE", "Title", "Hostname", "User", "IP", "OS", "Grade", "Device score", "Status",
              "First detected", "Last seen", "Age (days)", "Past SLA"]

    async def fetch(offset: int, limit: int) -> list[list]:
        out = []
        for f in (await db.execute(stmt.limit(limit).offset(offset))).scalars().all():
            r = _affected_row(f, vuln.cvss_base, vuln.attack_vector)
            out.append([cve, title, r["hostname"], r["user"], r["ip"], r["os"], r["device_grade"],
                        r["device_score"], r["status"], r["first_detected"], r["last_seen"], r["age_days"], r["past_sla"]])
        db.expunge_all()
        return out

    return await csv_paged_response(name, header, fetch)


# Code, Web app and Cloud findings are the organization's own (a file path, a site's URL, a check on its account),
# so someone who sees only some assets reads one only when it's on one of theirs. Infrastructure CVEs are public, and
# the page tells that person when none of their assets have it.
_PRIVATE_DOMAINS = ("code", "web", "cloud")


@router.get("/{vuln_id}")
async def get_vuln(
    vuln_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    tag: list[str] | None = _TAGS,
    _sla: None = Depends(sla.fresh),
):
    vuln = await _vuln_or_404(vuln_id, db)
    access = await device_scope(current_user, db)
    if access is not None and vuln.domain in _PRIVATE_DOMAINS and not (await db.execute(
            select(Finding.id).join(Device, Device.id == Finding.device_id)
            .where(Finding.vuln_id == vuln.id, access).limit(1))).first():
        raise HTTPException(404)   # the same answer as an id that doesn't exist
    scope = dq.with_tags(access, tag)
    n, old = (await db.execute(select(_affected_count(scope), _oldest(scope)).select_from(Vulnerability)
                               .where(Vulnerability.id == vuln.id))).one()
    out = _vuln_summary(vuln, n, old)
    if old is None:   # nothing open that this person can see: no age to show
        out.update(first_found=None, age_days=None, past_sla=False)
    out["scoped"] = scope is not None   # the page says so when none of this person's assets have it
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


async def _cloud_ports(db, device_ids: set[str]) -> dict[str, list]:
    """Cloud firewall openings per device for one page of rows (devices with no cloud record are absent)."""
    from api.models.cloud import CloudAsset
    if not device_ids:
        return {}
    out: dict[str, list] = {}
    for dev, ports in (await db.execute(select(CloudAsset.device_id, CloudAsset.ports)
                                        .where(CloudAsset.device_id.in_(list(device_ids))))).all():
        out.setdefault(str(dev), []).extend(ports or [])
    return out


def _affected_row(f: Finding, cvss: float | None = None, attack_vector: str | None = None,
                  cloud_ports: list | None = None) -> dict:
    d = f.device
    return {
        "id": str(f.id),
        "device_id": str(f.device_id),
        # a repository or site keeps its whole name ("acme/payments", "shop.acme.example"); hosts get the short one
        "hostname": (d.hostname if f.domain in ("code", "web") else dq.short_name(d.hostname)) if d else None,
        "domain": f.domain,
        "details": f.details if f.domain in ("code", "web") else cloud_findings.view(f, cvss),
        "contained": bool(d and (d.edr_contained or is_exempt(d))),
        "out_of_scope": bool(d and is_exempt(d)),
        "severity": dq.severity(cvss, bool(d and (d.edr_contained or is_exempt(d)))),
        "user": dq.user_label(d) if d else None,
        "ip": d.ip if d else None,
        "os": d.os if d else None,
        "device_grade": d.risk_grade.value if d and d.risk_grade else None,
        "device_score": d.risk_score if d else None,
        "raw_device_grade": d.raw_risk_grade if d else None,
        "raw_device_score": d.raw_risk_score if d else None,
        "status": f.status.value,
        "source": f.source,
        "exception_id": f.exception_id,
        "composite_score": f.composite_score,
        "risk_grade": f.risk_grade,
        "is_reachable": f.is_reachable,
        **reach_view(f, bool(d and (d.edr_contained or is_exempt(d))), attack_vector, cloud_ports),
        "first_detected": _iso(f.first_detected),
        "last_seen": _iso(f.last_seen),
        **age.view(f.first_detected, f.last_seen, f.status.value, cvss),
    }


def _vuln_summary(v: Vulnerability, affected_devices: int, oldest=None) -> dict:
    a = age.view(oldest if oldest is not None else v.first_found, None, "open", v.cvss_base)
    return {
        "first_found": _iso(oldest if oldest is not None else v.first_found),   # its oldest open finding
        "age_days": a["age_days"], "sla_days": a["sla_days"], "past_sla": a["past_sla"],
        "id": str(v.id),
        "cve_id": v.cve_id,
        "title": v.title,
        "domain": v.domain,
        "description": v.description,
        "cvss_base": v.cvss_base,
        "cvss_vector": v.cvss_vector,
        "epss_score": v.epss_score,
        "is_kev": v.is_kev,
        "pentest_exploited": bool(v.pentest_exploited),
        "kev_added_date": v.kev_added_date.isoformat() if v.kev_added_date else None,
        "attack_vector": v.attack_vector,
        "exploit_available": v.exploit_available,
        "source": v.source,
        "affected_devices": affected_devices or 0,
    }


class UpdateFindingStatusRequest(BaseModel):
    status: FindingStatus
    note: str | None = None
