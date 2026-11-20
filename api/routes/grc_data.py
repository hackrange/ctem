"""GRC views over FairTPRM's data, joined with CTEM's live control checks."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.grc import GrcCheckResult, GrcControl, GrcEvidence, GrcFramework, GrcMonitor, GrcRisk
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])
_WEAK = {"ineffective": "ineffective", "partially_effective": "only partially effective"}
_RISK_STATUS = {"identified", "assessing", "treating", "monitoring", "closed"}


def _iso(dt):
    return dt.isoformat() if dt else None


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def latest_results(db: AsyncSession) -> dict[str, GrcCheckResult]:
    newest = (select(GrcCheckResult.check_type, func.max(GrcCheckResult.measured_at).label("at"))
              .group_by(GrcCheckResult.check_type).subquery())
    rows = await db.execute(select(GrcCheckResult).join(newest, (GrcCheckResult.check_type == newest.c.check_type)
                                                        & (GrcCheckResult.measured_at == newest.c.at)))
    return {r.check_type: r for r in rows.scalars()}


async def _checks_by_control(db: AsyncSession) -> dict[str, list[str]]:
    """FairTPRM control id -> CTEM check types whose monitors feed it."""
    out: dict[str, list[str]] = {}
    for m in (await db.execute(select(GrcMonitor).where(GrcMonitor.check_type.like("ctem_%")))).scalars():
        for cid in m.control_ids or []:
            out.setdefault(cid, []).append(m.check_type)
    return out


@router.get("/frameworks")
async def frameworks(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(GrcFramework).where(GrcFramework.is_active == True)  # noqa: E712
                             .order_by(GrcFramework.code))).scalars().all()
    return {"frameworks": [{
        "id": str(f.id), "code": f.code, "name": f.name, "version": f.version, "compliance_year": f.compliance_year,
        "total_requirements": f.total_requirements, "implemented": f.implemented, "partial": f.partial,
        "in_progress": f.in_progress, "planned": f.planned, "not_applicable": f.not_applicable,
        "compliance_percentage": f.compliance_percentage, "synced_at": _iso(f.synced_at)} for f in rows]}


@router.get("/controls")
async def controls(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    feeds, latest = await _checks_by_control(db), await latest_results(db)
    rows = (await db.execute(select(GrcControl).where(GrcControl.is_active == True)  # noqa: E712
                             .order_by(GrcControl.control_ref))).scalars().all()
    return {"controls": [{
        "id": str(c.id), "control_ref": c.control_ref, "title": c.title, "control_type": c.control_type,
        "implementation_status": c.implementation_status, "effectiveness": c.effectiveness, "risk_level": c.risk_level,
        "last_tested_at": _iso(c.last_tested_at), "evidence_count": c.evidence_count, "frameworks": c.frameworks or [],
        "ctem_checks": [{"check_type": t, "result": latest[t].result if t in latest else None,
                         "measured_at": _iso(latest[t].measured_at) if t in latest else None}
                        for t in sorted(set(feeds.get(c.external_id, [])))],
    } for c in rows]}


def drift(risk: GrcRisk, controls: dict[str, GrcControl], feeds: dict[str, list[str]],
          latest: dict[str, GrcCheckResult]) -> list[str]:
    """Why a risk's recorded treatment may no longer match reality."""
    if (risk.status or "") == "closed":
        return []
    reasons = []
    if (risk.risk_treatment or "") in ("mitigate", "transfer"):
        linked = [controls[c] for c in risk.control_ids or [] if c in controls]
        if not linked:
            reasons.append("treated as mitigated, but no controls are linked to it")
        for c in linked:
            if c.effectiveness in _WEAK:
                reasons.append(f"control {c.control_ref or c.title} is {_WEAK[c.effectiveness]}")
            for t in feeds.get(c.external_id, []):
                r = latest.get(t)
                if r and r.result in ("fail", "error"):
                    reasons.append(f"CTEM check {t} is {'failing' if r.result == 'fail' else 'erroring'}: {r.summary[:160]}")
    if risk.review_date and risk.review_date < datetime.now(timezone.utc).date():
        reasons.append(f"review was due {risk.review_date.isoformat()}")
    return reasons


@router.get("/risks")
async def risks(status: str | None = None, drift_only: bool = False,
                _: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    from api.models.risk import ThirdPartyRisk
    if status is not None and status not in _RISK_STATUS:
        raise HTTPException(400, detail="Unknown status")
    q = select(GrcRisk).order_by(GrcRisk.residual_risk_score.desc().nulls_last(), GrcRisk.risk_ref)
    if status:
        q = q.where(GrcRisk.status == status)
    rows = (await db.execute(q)).scalars().all()
    controls = {c.external_id: c for c in (await db.execute(select(GrcControl))).scalars()}
    feeds, latest = await _checks_by_control(db), await latest_results(db)
    vendor_ids = {r.vendor_id for r in rows if r.vendor_id}
    vendors = {}
    if vendor_ids:
        found = await db.execute(select(ThirdPartyRisk.external_id, ThirdPartyRisk.supplier_name).where(
            ThirdPartyRisk.source == "fairtprm", ThirdPartyRisk.external_id.in_(vendor_ids)))
        vendors = dict(found.all())
    out = []
    for r in rows:
        reasons = drift(r, controls, feeds, latest)
        if drift_only and not reasons:
            continue
        out.append({
            "id": str(r.id), "risk_ref": r.risk_ref, "title": r.title, "risk_category": r.risk_category,
            "likelihood": r.likelihood, "impact": r.impact, "inherent_risk_score": r.inherent_risk_score,
            "residual_risk_score": r.residual_risk_score, "risk_treatment": r.risk_treatment, "status": r.status,
            "review_date": r.review_date.isoformat() if r.review_date else None,
            "vendor": vendors.get(r.vendor_id) if r.vendor_id else None,
            "controls": [controls[c].control_ref or controls[c].title for c in r.control_ids or [] if c in controls],
            "drift": reasons,
        })
    return {"risks": out, "total": len(out), "drifting": sum(1 for r in out if r["drift"])}


@router.get("/evidence-status")
async def evidence_status(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=30)
    rows = (await db.execute(select(GrcEvidence).order_by(GrcEvidence.valid_until))).scalars().all()
    expired = [e for e in rows if e.valid_until and _aware(e.valid_until) < now]
    expiring = [e for e in rows if e.valid_until and now <= _aware(e.valid_until) <= soon]

    def view(e: GrcEvidence) -> dict:
        return {"evidence_ref": e.evidence_ref, "title": e.title, "evidence_type": e.evidence_type,
                "collection_method": e.collection_method, "valid_until": _iso(e.valid_until)}
    return {"total": len(rows), "expired": len(expired), "expiring_30d": len(expiring),
            "current": len(rows) - len(expired), "expired_items": [view(e) for e in expired][:100],
            "expiring_items": [view(e) for e in expiring][:100]}


@router.get("/overview")
async def overview(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    from api.grc.checks import REGISTRY
    from api.integrations.fairtprm_grc import DASHBOARD_SETTING
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == DASHBOARD_SETTING))).scalar_one_or_none()
    try:
        dashboard = json.loads(row.value) if row and row.value else None
    except ValueError:
        dashboard = None
    latest = await latest_results(db)
    monitored = {m.check_type for m in (await db.execute(select(GrcMonitor).where(GrcMonitor.check_type.like("ctem_%")))).scalars()}
    return {"fairtprm": dashboard, "checks": [{
        "check_type": c.check_type, "name": c.name, "suggested_controls": list(c.controls),
        "used_by_fairtprm": c.check_type in monitored,
        "result": latest[c.check_type].result if c.check_type in latest else None,
        "summary": latest[c.check_type].summary if c.check_type in latest else None,
        "measured_at": _iso(latest[c.check_type].measured_at) if c.check_type in latest else None,
    } for c in REGISTRY.values()]}
