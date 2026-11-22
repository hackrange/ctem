"""Device inventory and risk API. BOLA-safe -- every object fetch verifies access."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.device_scope import device_scope
from api.core import sla
from api.core import finding_age as age
from api.auth.rbac import can_access_device, require_permission
from api.core.csv_export import csv_paged_response
from api.core.db import get_session
from api.core.device_scope_exempt import is_exempt
from api.core.device_scope_exempt import view as exempt_view
from api.models.device import Device, DeviceTag, DeviceType
from api.models.user import User
from api.models.vuln import Finding, FindingStatus, Vulnerability
from api.routes import device_query as dq
from api.scoring.compensating import reach_view

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


async def _filtered(user, db, q, grade, device_type, source, tag, status=None, ad_stale_days=None, card=None):
    return dq.build_query(await device_scope(user, db), q, grade, device_type, source, tag, status, ad_stale_days, card)


def _card(os_family: str | None = Query(None, pattern="^(windows|linux|macos|network|mobile|hypervisor|unix|other|unknown)$"),
          missing: str | None = Query(None, pattern="^(edr|scanner|either)$"),
          active_days: int | None = Query(None, ge=1, le=3650), new_days: int | None = Query(None, ge=1, le=3650),
          compute: bool = Query(False), ad_tools_quiet_days: int | None = Query(None, ge=1, le=3650),
          asset: str | None = Query(None, pattern="^(hosts|repositories|sites)$"),
          fix: str | None = Query(None, max_length=160, pattern=r"^[A-Za-z0-9._:@/+\-]+$")) -> dict:
    """Filters a dashboard card links with (see device_query.card_filters)."""
    return {"os_family": os_family, "missing": missing, "active_days": active_days, "new_days": new_days, "compute": compute,
            "ad_tools_quiet_days": ad_tools_quiet_days, "asset": asset, "fix": fix}


_STATUS_FILTER = Query(None, pattern="^(assigned|shipped|lost|stolen|returned|contained|edr_hidden|out_of_scope)$")


_TAGS = Query(None, max_length=128, description="Tag name; repeat to require several")
_STALE = Query(None, ge=1, le=3650, description="AD computer objects with no logon for this many days")


@router.get("")
async def list_devices(
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    device_type: DeviceType | None = None,
    grade: str | None = Query(None, max_length=8),
    source: str | None = Query(None, max_length=64),
    status: str | None = _STATUS_FILTER,
    tag: list[str] | None = _TAGS,
    ad_stale_days: int | None = _STALE,
    card: dict = Depends(_card),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    stmt = await _filtered(current_user, db, q, grade, device_type, source, tag, status, ad_stale_days, card)
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
    status: str | None = _STATUS_FILTER,
    tag: list[str] | None = _TAGS,
    ad_stale_days: int | None = _STALE,
    card: dict = Depends(_card),
    by: str = Query("environment", pattern="^(environment|application)$"),
):
    """Dashboard counts across every device the user can see (not one page of them). by: the tag role to break
    the counts down by (environment for hosts and sites, application for repositories)."""
    stmt = await _filtered(current_user, db, q, grade, device_type, source, tag, status, ad_stale_days, card)
    grades = {g: 0 for g in ("A", "B", "C", "D", "F")}
    ungraded = kev_devices = 0
    for g, n, kev in (await db.execute(dq.grade_counts_query(stmt))).all():
        kev_devices += kev
        if g is None:
            ungraded += n
        else:
            grades[g.value if hasattr(g, "value") else str(g)] = n
    from api.core import tag_roles
    roles = await tag_roles.ensure(db)
    rules = next((r.rules for r in roles if r.key == by), ())
    merged: dict[str, dict] = {}
    for env, n, avg, crit in (await db.execute(dq.env_breakdown_query(stmt, rules))).all():
        m = tag_roles.match(env, roles) if env else None
        label = m[1] if m and m[0] == by else "Unknown"
        e = merged.setdefault(label, {"env": label, "devices": 0, "_sum": 0.0, "critical": 0})
        e["devices"] += n
        e["_sum"] += float(avg or 0) * n
        e["critical"] += int(crit or 0)
    envs = [{"env": e["env"], "devices": e["devices"], "critical": e["critical"],
             "avg_score": round(e["_sum"] / e["devices"], 1) if e["devices"] else None} for e in merged.values()]
    envs.sort(key=lambda e: -e["devices"])
    exposed = (await db.execute(stmt.order_by(None).with_only_columns(func.count()).where(Device.is_internet_exposed.is_(True)))).scalar_one()
    return {"total": sum(grades.values()) + ungraded, "grades": grades, "ungraded": ungraded,
            "kev_devices": kev_devices, "internet_exposed": exposed, "environments": envs, "by": by}


@router.get("/export")
async def export_devices(
    current_user: User = Depends(require_permission("devices", "read")),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    device_type: DeviceType | None = None,
    grade: str | None = Query(None, max_length=8),
    source: str | None = Query(None, max_length=64),
    status: str | None = _STATUS_FILTER,
    tag: list[str] | None = _TAGS,
    ad_stale_days: int | None = _STALE,
    card: dict = Depends(_card),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
):
    stmt = dq.with_relations(dq.sorted_query(await _filtered(current_user, db, q, grade, device_type, source, tag, status, ad_stale_days, card),
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
        select(Device).options(selectinload(Device.tags).selectinload(DeviceTag.tag), selectinload(Device.owner),
                               *dq.ASSIGNMENT_LOAD)
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
    from api.cloud.exposure import for_device
    cloud = await for_device(db, device.id)   # instances, public IPs, attached firewalls and open ports
    base.update({
        "cloud": cloud,
        # Every public address observed for the device, with where it was seen
        "public_ips": [{"ip": ip, "source": c["provider"].upper()} for c in cloud for ip in c["public_ips"]],
        "fqdn": dq.full_name(device),
        "mac_address": device.mac_address,
        "os_version": device.os_version,
        "ad_last_logon": device.ad_last_logon.isoformat() if device.ad_last_logon else None,
        "edr_last_seen": device.edr_last_seen.isoformat() if device.edr_last_seen else None,
        "last_login_user": device.last_login_user,
        "recent_logins": device.recent_logins or [],
        "detected_user_upn": device.owner.upn if device.owner is not None else None,
        "detected_user_title": device.owner.title if device.owner is not None else None,
        "out_of_scope": exempt_view(device),
        "can_set_scope": bool({"admin", "cyber"}.intersection(current_user.role_names)),
        "score_why": await _score_why(db, device.id),
        "related_owners": await _related_owners(db, device.id, current_user),
    })
    return base


async def _related_owners(db, device_id: str, user) -> dict:
    """Owner roles this asset's own tags don't give, from other assets of the same application (for example a site
    whose scanner sends no application owner, while the application's repository has one). Read through the tag
    mapping, so any tool's owner tags count. Only roles the asset lacks; at most 500 related assets are read, and
    only those the viewer may open themselves, so owners never leak from assets outside their scope."""
    from api.core import tag_roles
    from api.models.tag import Tag
    roles = await tag_roles.ensure(db)
    mine = [n for (n,) in (await db.execute(select(Tag.name).join(DeviceTag, DeviceTag.tag_id == Tag.id)
                                            .where(DeviceTag.device_id == device_id))).all()]
    keys = ("executive_owner", "technical_owner", "application_owner")
    missing = [k for k in keys if not tag_roles.values(mine, k, roles)]
    app_tags = [t for t in mine if (m := tag_roles.match(t, roles)) and m[0] == "application"]
    if not missing or not app_tags:
        return {}
    via = tag_roles.values(app_tags, "application", roles)[0]
    others = [i for (i,) in (await db.execute(select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(
        Tag.name.in_(app_tags), DeviceTag.device_id != device_id).distinct().limit(500))).all()]
    if others and not set(user.role_names) & {"admin", "cyber", "inventory"}:   # everyone else: per asset
        rows = (await db.execute(select(Device).options(selectinload(Device.tags))
                                 .where(Device.id.in_(others)))).scalars().all()
        others = [d.id for d in rows if await can_access_device(user, d, db)]
    if not others:
        return {}
    names = [n for (n,) in (await db.execute(select(Tag.name).join(DeviceTag, DeviceTag.tag_id == Tag.id)
                                             .where(DeviceTag.device_id.in_(others)).distinct())).all()]
    out = {}
    for k in missing:
        vals = tag_roles.values(names, k, roles)
        if vals:
            out[k] = {"values": vals[:5], "via": via}
    return out


async def _score_why(db, device_id: str) -> dict | None:
    """Why a repository or site scored what it did (kept by the scoring engine), for the asset page."""
    import json

    from api.models.risk import RiskScore
    raw = (await db.execute(select(RiskScore.score_breakdown).where(RiskScore.entity_type == "device",
                                                                    RiskScore.entity_id == device_id))).scalar_one_or_none()
    try:
        out = json.loads(raw) if raw else None
    except ValueError:
        return None
    return out if isinstance(out, dict) else None


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
    asc = (order or "").lower() == "asc"
    if sort == "age":   # oldest first is the highest age
        col, asc = Finding.first_detected, not asc
    else:
        col = _FINDING_SORTS.get(sort or "", Vulnerability.cvss_base)
    direction = col.asc() if asc else col.desc()
    return stmt.order_by(direction.nullslast(), Vulnerability.title.asc(), Finding.id.asc()).options(selectinload(Finding.vuln))


_STATUS_PATTERN = "^(active|all|" + "|".join(s.value for s in FindingStatus) + ")$"


@router.get("/{device_id}/findings")
async def get_device_findings(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    _findings: User = Depends(require_permission("findings", "read")),  # inventory sees devices, not vulns
    db: AsyncSession = Depends(get_session),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    q: str | None = Query(None, max_length=200),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    _sla: None = Depends(sla.fresh),
):
    device = await _visible_device(device_id, current_user, db)
    stmt = _findings_query(device.id, status, q)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(_sorted_findings(stmt, sort, order).limit(limit).offset(offset))).scalars().all()
    contained = bool(device.edr_contained) or is_exempt(device)   # Not In Scope reads like contained: nothing counts
    from api.cloud.exposure import for_device
    cloud = await for_device(db, device.id)
    cloud_ports = [p for a in cloud for p in a["ports"]] if cloud else None
    from api.scoring.engine import _edr_context, _edr_facts
    from api.scoring.compensating import ControlContext, _edr
    edr = await _edr_facts(device, db)

    def protections(f) -> list[str]:
        """What the EDR does about this finding here, as the score counted it (api/scoring/compensating.py)."""
        extra = _edr_context(edr, f)
        if not extra:
            return []
        ctx = ControlContext(edr_active=True, edr_vendor=device.edr_vendor, attack_vector=f.vuln.attack_vector if f.vuln else None,
                             **extra)
        return ([extra["host_firewall"][1]] if extra.get("host_firewall") else []) + _edr(1.0, ctx)[1]
    return {"findings": [{**_finding_summary(f, contained, cloud_ports), "protections": protections(f)} for f in rows],
            "total": total, "limit": limit, "offset": offset, "contained": contained}


@router.get("/{device_id}/findings/export")
async def export_device_findings(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    _findings: User = Depends(require_permission("findings", "read")),  # inventory sees devices, not vulns
    db: AsyncSession = Depends(get_session),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    q: str | None = Query(None, max_length=200),
    sort: str | None = Query(None, max_length=32),
    order: str | None = Query(None, pattern="^(asc|desc)$"),
    _sla: None = Depends(sla.fresh),
):
    device = await _visible_device(device_id, current_user, db)
    hostname, contained = dq.short_name(device.hostname), bool(device.edr_contained) or is_exempt(device)
    stmt = _sorted_findings(_findings_query(device.id, status, q), sort, order)
    header = ["Hostname", "Severity", "CVE", "Title", "CVSS", "EPSS", "KEV", "Score", "Status", "First detected",
              "Last seen", "Age (days)", "Past SLA", "Source"]

    async def fetch(offset: int, limit: int) -> list[list]:
        rows = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
        out = [[hostname, dq.severity(f.vuln.cvss_base, contained), f.vuln.cve_id, f.vuln.title, f.vuln.cvss_base, f.vuln.epss_score, f.vuln.is_kev,
                f.composite_score, f.status.value, _iso(f.first_detected), _iso(f.last_seen),
                *(lambda a: (a["age_days"], a["past_sla"]))(age.view(f.first_detected, f.last_seen, f.status.value, f.vuln.cvss_base)),
                f.source] for f in rows]
        db.expunge_all()
        return out

    return await csv_paged_response(f"findings-{hostname}", header, fetch)


def _iso(dt):
    return dt.isoformat() if dt else None


def _finding_summary(f: Finding, contained: bool = False, cloud_ports: list | None = None) -> dict:
    v = f.vuln
    return {
        "id": str(f.id),
        "severity": dq.severity(v.cvss_base if v else None, contained),
        "contained": contained,
        "vuln_id": str(f.vuln_id),
        "cve_id": v.cve_id if v else None,
        "title": v.title if v else None,
        "cvss_base": v.cvss_base if v else None,
        "epss_score": v.epss_score if v else None,
        "is_kev": v.is_kev if v else False,
        "composite_score": f.composite_score,
        "risk_grade": f.risk_grade,
        "raw_score": f.raw_score,
        "raw_grade": f.raw_grade,
        "status": f.status.value,
        "source": f.source,
        "domain": f.domain,
        "details": f.details if f.domain in ("code", "web") else None,   # where and how, for Code and Web app findings
        "exception_id": f.exception_id,
        "is_reachable": f.is_reachable,
        "reachability_source": f.reachability_source,
        "in_attack_chain": f.in_attack_chain,
        **reach_view(f, contained, v.attack_vector if v else None, cloud_ports),
        "first_detected": _iso(f.first_detected),
        **age.view(f.first_detected, f.last_seen, f.status.value, v.cvss_base if v else None),
        "last_seen": _iso(f.last_seen),
    }
