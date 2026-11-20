"""FairTPRM assessment results and audits on the GRC page."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.grc import GrcAssessment, GrcAudit
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])
_OPEN_FINDING = {"open", "in_remediation"}


def _iso(v):
    return v.isoformat() if v else None


def _summary(a: GrcAssessment) -> dict:
    gaps = a.gaps or []
    return {"id": str(a.id), "ref": a.assessment_ref, "title": a.title, "type": a.assessment_type, "status": a.status,
            "fairscore": a.fairscore, "compliance_pct": a.compliance_pct, "progress": a.progress or {},
            "planned_start": _iso(a.planned_start), "planned_end": _iso(a.planned_end),
            "completed": _iso(a.actual_end), "updated_at": _iso(a.source_updated_at), "synced_at": _iso(a.synced_at),
            "non_conforming": sum(1 for g in gaps if g.get("status") == "non_conforming"),
            "partial": sum(1 for g in gaps if g.get("status") == "partial")}


def _newest(a: GrcAssessment) -> tuple:
    day = a.actual_end or a.planned_end or a.planned_start
    stamp = a.source_updated_at or a.synced_at
    return (day.toordinal() if day else 0, stamp.timestamp() if stamp else 0.0)


async def _available(db: AsyncSession) -> bool:
    from api.integrations.fairtprm_grc import ASSESSMENTS_SETTING
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == ASSESSMENTS_SETTING))).scalar_one_or_none()
    return row is None or row.value != "0"  # unknown until the first sync; say so only once FairTPRM answered 404


@router.get("/assessments")
async def assessments(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    """Newest first; the latest completed one is the current maturity picture."""
    rows = (await db.execute(select(GrcAssessment))).scalars().all()
    rows = sorted(rows, key=_newest, reverse=True)
    items = [_summary(a) for a in rows]
    latest = next((a for a in rows if a.status == "completed"), rows[0] if rows else None)
    return {"assessments": items, "available": await _available(db),
            "latest": {**_summary(latest), "domain_scores": latest.domain_scores or [],
                       "framework_compliance": latest.framework_compliance or []} if latest else None}


@router.get("/assessments/{assessment_id}")
async def assessment(assessment_id: uuid.UUID, _: User = Depends(require_permission("grc", "read")),
                     db: AsyncSession = Depends(get_session)):
    a = (await db.execute(select(GrcAssessment).where(GrcAssessment.id == str(assessment_id)))).scalar_one_or_none()
    if a is None:
        raise HTTPException(404, detail="Assessment not found")
    return {**_summary(a), "domain_scores": a.domain_scores or [], "framework_compliance": a.framework_compliance or [],
            "gaps": a.gaps or []}


@router.get("/audits")
async def audits(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(GrcAudit))).scalars().all()
    rows = sorted(rows, key=lambda a: (a.status == "closed", -(a.planned_start.toordinal() if a.planned_start else 0)))
    out = []
    for a in rows:
        f = a.findings or []
        out.append({"id": str(a.id), "ref": a.audit_ref, "title": a.title, "type": a.audit_type, "status": a.status,
                    "framework": a.framework_code, "firm": a.audit_firm, "planned_start": _iso(a.planned_start),
                    "planned_end": _iso(a.planned_end), "completed": _iso(a.actual_end),
                    "certification_valid_until": _iso(a.certification_valid_until),
                    "findings_count": a.findings_count or len(f), "critical_findings": a.critical_findings,
                    "open_findings": sum(1 for x in f if x.get("status") in _OPEN_FINDING),
                    "findings": f})
    return {"audits": out}
