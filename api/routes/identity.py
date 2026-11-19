"""Identity risk API -- ITDR alerts, posture findings, shadow SaaS/AI, identity scores."""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.identity import (
    IdentityRiskScore,
    IdentityThreat,
    ItdrAlertStatus,
    PostureFinding,
    SaasAppRecord,
)
from api.models.user import User

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])


# ── ITDR Threats ──────────────────────────────────────────────────────────────

@router.get("/threats")
async def list_itdr_threats(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    severity: str | None = None,
    status: ItdrAlertStatus | None = None,
    source: str | None = None,
    threat_type: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    """Active ITDR threat alerts from Grip Security (and future identity sources)."""
    q = select(IdentityThreat).order_by(IdentityThreat.detected_at.desc())
    if severity:
        q = q.where(IdentityThreat.severity == severity.lower())
    if status:
        q = q.where(IdentityThreat.status == status)
    else:
        q = q.where(IdentityThreat.status == ItdrAlertStatus.active)
    if source:
        q = q.where(IdentityThreat.source == source)
    if threat_type:
        q = q.where(IdentityThreat.threat_type == threat_type)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    result = await db.execute(q.offset(offset).limit(limit))
    threats = result.scalars().all()

    return {
        "threats": [_serialize_threat(t) for t in threats],
        "total": total,
    }


@router.get("/threats/summary")
async def itdr_summary(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """Counts by severity and type for dashboard widgets."""
    result = await db.execute(
        select(
            IdentityThreat.severity,
            IdentityThreat.threat_type,
            func.count().label("n"),
        )
        .where(IdentityThreat.status == ItdrAlertStatus.active)
        .group_by(IdentityThreat.severity, IdentityThreat.threat_type)
    )
    rows = result.all()
    by_sev: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for sev, ttype, n in rows:
        by_sev[sev] = by_sev.get(sev, 0) + n
        by_type[str(ttype.value if hasattr(ttype, "value") else ttype)] = (
            by_type.get(str(ttype.value if hasattr(ttype, "value") else ttype), 0) + n
        )
    return {"by_severity": by_sev, "by_type": by_type, "total_active": sum(by_sev.values())}


# ── Posture Findings ──────────────────────────────────────────────────────────

@router.get("/posture")
async def list_posture_findings(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    severity: str | None = None,
    resolved: bool = False,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    """Identity posture findings (MFA gaps, excessive OAuth, dormant admins, etc.)."""
    q = select(PostureFinding).where(PostureFinding.is_resolved == resolved).order_by(
        PostureFinding.detected_at.desc()
    )
    if severity:
        q = q.where(PostureFinding.severity == severity.lower())

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(q.offset(offset).limit(limit))
    findings = result.scalars().all()

    return {
        "findings": [
            {
                "id": str(f.id),
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "app_name": f.app_name,
                "user_display": f.user_display,
                "affected_count": f.affected_count,
                "is_resolved": f.is_resolved,
                "detected_at": f.detected_at.isoformat() if f.detected_at else None,
                "source": f.source,
            }
            for f in findings
        ],
        "total": total,
    }


# ── Shadow SaaS + Shadow AI ────────────────────────────────────────────────────

@router.get("/saas-apps")
async def list_saas_apps(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    app_type: Literal["all", "shadow_saas", "shadow_ai", "ai_agent"] = "all",
    sanctioned: bool | None = None,
    risk_level: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    """
    Discovered SaaS applications from Grip Security.
    app_type=shadow_saas: non-AI shadow apps
    app_type=shadow_ai: apps with Grip aiDepth signal
    app_type=ai_agent: Copilot/GPT agent instances
    """
    q = select(SaasAppRecord).order_by(SaasAppRecord.risk_score.desc().nullslast())

    if app_type == "shadow_saas":
        q = q.where(SaasAppRecord.is_shadow_ai == False, SaasAppRecord.source == "grip")  # noqa: E712
    elif app_type == "shadow_ai":
        q = q.where(SaasAppRecord.is_shadow_ai == True, SaasAppRecord.source == "grip")   # noqa: E712
    elif app_type == "ai_agent":
        q = q.where(SaasAppRecord.source == "grip_ai_agent")

    if sanctioned is not None:
        q = q.where(SaasAppRecord.is_sanctioned == sanctioned)
    if risk_level:
        q = q.where(SaasAppRecord.risk_level == risk_level.lower())

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(q.offset(offset).limit(limit))
    apps = result.scalars().all()

    return {
        "apps": [
            {
                "id": str(a.id),
                "app_name": a.app_name,
                "app_category": a.app_category,
                "is_shadow_ai": a.is_shadow_ai,
                "is_sanctioned": a.is_sanctioned,
                "risk_level": a.risk_level,
                "risk_score": a.risk_score,
                "user_count": a.user_count,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                "source": a.source,
            }
            for a in apps
        ],
        "total": total,
    }


@router.get("/saas-apps/summary")
async def saas_summary(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """Counts for shadow SaaS, shadow AI, unsanctioned -- for the identity risk dashboard panel."""
    async def count_where(*filters):
        q = select(func.count(SaasAppRecord.id))
        for f in filters:
            q = q.where(f)
        return (await db.execute(q)).scalar_one()

    return {
        "total_apps": await count_where(),
        "shadow_saas": await count_where(SaasAppRecord.is_shadow_ai == False, SaasAppRecord.source == "grip"),  # noqa: E712
        "shadow_ai": await count_where(SaasAppRecord.is_shadow_ai == True, SaasAppRecord.source == "grip"),    # noqa: E712
        "ai_agents": await count_where(SaasAppRecord.source == "grip_ai_agent"),
        "unsanctioned": await count_where(SaasAppRecord.is_sanctioned == False),                                # noqa: E712
        "critical_risk": await count_where(SaasAppRecord.risk_level == "critical"),
        "high_risk": await count_where(SaasAppRecord.risk_level == "high"),
    }


# ── Identity Risk Scores ──────────────────────────────────────────────────────

@router.get("/scores")
async def list_identity_scores(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    min_score: float = 0,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    """Per-identity composite risk scores, highest risk first."""
    q = (
        select(IdentityRiskScore)
        .where(IdentityRiskScore.composite_identity_score >= min_score)
        .order_by(IdentityRiskScore.composite_identity_score.desc())
    )
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(q.offset(offset).limit(limit))
    scores = result.scalars().all()

    return {
        "scores": [
            {
                "id": str(s.id),
                "user_display": s.user_display,
                "composite_identity_score": s.composite_identity_score,
                "itdr_score": s.itdr_score,
                "posture_score": s.posture_score,
                "shadow_saas_score": s.shadow_saas_score,
                "shadow_ai_score": s.shadow_ai_score,
                "active_itdr_alerts": s.active_itdr_alerts,
                "posture_findings": s.posture_findings,
                "shadow_saas_apps": s.shadow_saas_apps,
                "shadow_ai_apps": s.shadow_ai_apps,
                "last_synced": s.last_synced.isoformat() if s.last_synced else None,
            }
            for s in scores
        ],
        "total": total,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize_threat(t: IdentityThreat) -> dict:
    return {
        "id": str(t.id),
        "source": t.source,
        "threat_type": t.threat_type.value if hasattr(t.threat_type, "value") else str(t.threat_type),
        "severity": t.severity,
        "status": t.status.value if hasattr(t.status, "value") else str(t.status),
        "title": t.title,
        "description": t.description,
        "user_display": t.user_display,
        "app_name": t.app_name,
        "mitre_technique_id": t.mitre_technique_id,
        "country": t.country,
        "detected_at": t.detected_at.isoformat() if t.detected_at else None,
        "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
    }
