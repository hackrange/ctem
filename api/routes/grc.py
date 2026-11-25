"""GRC / FairTPRM integration -- expose risk data and ingest compliance evidence."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])


@router.get("/risk-export")
async def export_risk_for_grc(
    _: User = Depends(require_permission("grc", "read")),
    db: AsyncSession = Depends(get_session),
):
    """Latest result of every CTEM control check, with suggested control mappings, for any GRC tool."""
    from api.routes.grc_data import latest_results
    from api.rules.custom import all_checks

    latest = await latest_results(db)
    return {
        "source": "open-ctem",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "checks": [{
            "check_type": c.check_type, "name": c.name, "suggested_controls": list(c.controls),
            "result": latest[c.check_type].result if c.check_type in latest else None,
            "summary": latest[c.check_type].summary if c.check_type in latest else None,
            "measured_at": latest[c.check_type].measured_at.isoformat() if c.check_type in latest else None,
        } for c in (await all_checks(db)).values()],
    }


@router.get("/compliance-status")
async def get_compliance_status(
    _: User = Depends(require_permission("grc", "read")),
    db: AsyncSession = Depends(get_session),
    framework: str | None = None,
):
    """Control effectiveness from FairTPRM, optionally narrowed to one framework code (e.g. ISO27001)."""
    from api.models.grc import GrcControl

    if framework is not None and not re.fullmatch(r"[A-Za-z0-9 ._:-]{1,50}", framework):
        raise HTTPException(400, detail="Unknown framework")
    rows = (await db.execute(select(GrcControl).where(GrcControl.is_active == True))).scalars().all()  # noqa: E712
    if framework:
        rows = [c for c in rows if framework.lower() in [f.lower() for f in (c.frameworks or [])]]
    return {"framework": framework, "total": len(rows), "controls": [{
        "control_ref": c.control_ref, "title": c.title, "implementation_status": c.implementation_status,
        "effectiveness": c.effectiveness or "not_tested",
        "last_tested_at": c.last_tested_at.isoformat() if c.last_tested_at else None,
    } for c in rows]}


# ── Third-party risk (FairTPRM) endpoints ─────────────────────────────────────

@router.get("/suppliers")
async def list_suppliers(
    _: User = Depends(require_permission("grc", "read")),
    db: AsyncSession = Depends(get_session),
    tier: str | None = None,
    min_score: float = 0,
    limit: int = 50,
    offset: int = 0,
):
    """Supplier risk scores synced from FairTPRM."""
    from sqlalchemy import func
    from api.models.risk import ThirdPartyRisk

    q = select(ThirdPartyRisk).order_by(ThirdPartyRisk.risk_score.desc())
    if tier:
        q = q.where(ThirdPartyRisk.tier == tier)
    if min_score:
        q = q.where(ThirdPartyRisk.risk_score >= min_score)

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(q.offset(offset).limit(limit))
    suppliers = result.scalars().all()

    return {
        "suppliers": [
            {
                "id": str(s.id),
                "supplier_name": s.supplier_name,
                "tier": s.tier,
                "status": s.status,
                "risk_score": s.risk_score if s.risk_grade != "-" else None,
                "risk_grade": s.risk_grade,
                "open_gaps": s.open_gaps,
                "last_assessment": s.last_assessment.isoformat() if s.last_assessment else None,
                "next_review": s.next_review.isoformat() if s.next_review else None,
                "source": s.source,
            }
            for s in suppliers
        ],
        "total": total,
    }


@router.get("/suppliers/{supplier_id}/gaps")
async def list_supplier_gaps(
    supplier_id: str,
    _: User = Depends(require_permission("grc", "read")),
    db: AsyncSession = Depends(get_session),
):
    """Control gaps for one supplier, for anyone with grc:read.

    Suppliers are organization-wide records synced from the GRC tool: no CTEM user owns one, and every grc grant is
    seeded at 'all' scope (tests/test_grc.py pins that), so the same people can already list every supplier at
    /suppliers. If a narrower grc scope is ever added, this route and /suppliers need a scope check first."""
    from api.models.risk import ThirdPartyControlGap, ThirdPartyRisk
    import uuid as _uuid

    try:
        sid = str(_uuid.UUID(supplier_id))
    except ValueError:
        raise HTTPException(404)

    # Verify supplier exists (404 not 403)
    s_result = await db.execute(select(ThirdPartyRisk).where(ThirdPartyRisk.id == sid))
    if not s_result.scalar_one_or_none():
        raise HTTPException(404)

    result = await db.execute(
        select(ThirdPartyControlGap)
        .where(ThirdPartyControlGap.supplier_id == sid)
        .order_by(ThirdPartyControlGap.severity)
    )
    gaps = result.scalars().all()
    return {
        "gaps": [
            {
                "id": str(g.id),
                "control_name": g.control_name,
                "description": g.description,
                "severity": g.severity,
                "is_resolved": g.is_resolved,
                "detected_at": g.detected_at.isoformat() if g.detected_at else None,
            }
            for g in gaps
        ],
        "total": len(gaps),
    }
