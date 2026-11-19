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
        except Exception:
            continue
        control_id = r.key.replace(f"grc_evidence_{framework}_", "")
        expired = False
        if d.get("expires_at"):
            try:
                exp = datetime.fromisoformat(d["expires_at"])
                expired = now > exp.replace(tzinfo=timezone.utc if exp.tzinfo is None else exp.tzinfo)
            except Exception:
                pass
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
