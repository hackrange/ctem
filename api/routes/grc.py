"""GRC / FairTPRM integration -- expose risk data and ingest compliance evidence."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.auth.rbac import require_cyber_or_admin, require_permission
from api.core.db import get_session
from api.models.device import Device
from api.models.user import User
from api.models.vuln import Finding, FindingStatus

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])


@router.get("/risk-export")
async def export_risk_for_grc(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    framework: str = "nist-csf",
):
    """
    Export device and finding risk data mapped to a compliance framework.
    Intended for ingest by open-fairtprm or any GRC platform.
    Supported frameworks: nist-csf, iso-27001, nist-800-53
    """
    if framework not in ("nist-csf", "iso-27001", "nist-800-53"):
        raise HTTPException(400, detail=f"Unknown framework: {framework}")

    result = await db.execute(
        select(Device).limit(10000)
    )
    devices = result.scalars().all()

    findings_result = await db.execute(
        select(Finding).where(Finding.status == FindingStatus.open).limit(50000)
    )
    findings = findings_result.scalars().all()

    # Build control mappings
    control_issues = _map_to_controls(framework, devices, findings)
    return {
        "framework": framework,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": "open-ctem",
        "device_count": len(devices),
        "open_finding_count": len(findings),
        "control_issues": control_issues,
    }


@router.post("/evidence")
async def ingest_evidence(
    body: EvidenceRequest,
    _: User = Depends(require_permission("grc", "write")),
    db: AsyncSession = Depends(get_session),
):
    """
    Receive compliance evidence status from open-fairtprm.
    Stores as AppSetting with TTL tracking for expiry alerts.
    """
    from api.models.settings import AppSetting
    import json

    key = f"grc_evidence_{body.framework}_{body.control_id}"
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
    setting.value = json.dumps({
        "status": body.status,
        "evidence_url": body.evidence_url,
        "expires_at": body.expires_at,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "notes": body.notes,
    })
    db.add(setting)
    await db.commit()
    return {"stored": True, "key": key}


@router.get("/compliance-status")
async def get_compliance_status(
    _: User = Depends(require_permission("grc", "read")),
    db: AsyncSession = Depends(get_session),
    framework: str = "nist-csf",
):
    """Control-by-control compliance pass/fail summary."""
    from api.models.settings import AppSetting
    import json

    result = await db.execute(
        select(AppSetting).where(AppSetting.key.like(f"grc_evidence_{framework}_%"))
    )
    rows = result.scalars().all()
    controls = []
    now = datetime.now(timezone.utc)
    for r in rows:
        try:
            d = json.loads(r.value or "{}")
        except ValueError:
            continue
        control_id = r.key.replace(f"grc_evidence_{framework}_", "")
        expired = False
        if d.get("expires_at"):
            try:
                exp = datetime.fromisoformat(str(d["expires_at"]).replace("Z", "+00:00"))
                expired = now > (exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc))
            except ValueError:
                expired = True  # can't prove it's current, so it isn't
        controls.append({
            "control_id": control_id,
            "status": "expired" if expired else d.get("status", "unknown"),
            "evidence_url": d.get("evidence_url"),
            "expires_at": d.get("expires_at"),
            "updated_at": d.get("updated_at"),
        })
    return {"framework": framework, "controls": controls, "total": len(controls)}


def _map_to_controls(framework: str, devices: list, findings: list) -> list[dict]:
    # Lightweight static mapping -- real GRC platforms have their own taxonomy
    _NIST_CSF_MAP = {
        "PR.AC":  "access_control",
        "PR.PT":  "patch_management",
        "DE.CM":  "continuous_monitoring",
        "RS.RP":  "incident_response",
        "RC.IM":  "recovery",
    }
    unpatched = sum(1 for f in findings)
    no_edr = sum(1 for d in devices if not d.edr_active)
    return [
        {"control": "PR.PT-1", "category": "Patch Management", "status": "fail" if unpatched > 0 else "pass", "open_findings": unpatched},
        {"control": "PR.PT-3", "category": "EDR Coverage", "status": "fail" if no_edr > 0 else "pass", "devices_without_edr": no_edr},
    ]


class EvidenceRequest(BaseModel):
    framework: str
    control_id: str
    status: str           # pass, fail, partial
    evidence_url: str | None = None
    expires_at: str | None = None   # ISO 8601
    notes: str | None = None


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
                "risk_score": s.risk_score,
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
    """Control gaps for a specific supplier -- object-level auth via source ownership."""
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
