"""Scoring orchestrator. Recalculates risk for all devices and users."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.models.device import Device
from api.models.risk import RiskScore, RiskScoreHistory
from api.models.vuln import Finding, FindingStatus
from api.scoring.compensating import ControlContext
from api.scoring.device_score import compute_device_score, score_finding
from api.scoring.user_score import compute_user_score


async def recalculate_device(device: Device, db: AsyncSession) -> RiskScore:
    """Recalculate and persist the risk score for a single device."""
    findings_result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.vuln))
        .where(
            Finding.device_id == device.id,
            Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]),
        )
    )
    findings = findings_result.scalars().all()

    # Build the per-finding context list
    findings_data = []
    days_offline = _days_since(device.last_seen)
    for f in findings:
        ctx = ControlContext(
            edr_active=device.edr_active,
            edr_vendor=device.edr_vendor,
            is_internet_exposed=device.is_internet_exposed,
            device_offline_days=days_offline,
            nodezero_confirmed_exploitable=bool(f.is_reachable and f.reachability_source == "horizon3"),
            nodezero_confirmed_not_exploitable=bool(f.is_reachable is False and f.reachability_source == "horizon3"),
        )
        findings_data.append({
            "cvss_base": f.vuln.cvss_base or 0.0,
            "epss_score": f.vuln.epss_score or 0.0,
            "is_kev": f.vuln.is_kev,
            "asset_criticality": 0.7 if device.device_type.value == "server" else 0.5,
            "is_reachable": f.is_reachable,
            "control_context": ctx,
        })

    score, grade = compute_device_score(findings_data)

    # Upsert the current score
    result = await db.execute(
        select(RiskScore).where(
            RiskScore.entity_type == "device",
            RiskScore.entity_id == device.id,
        )
    )
    risk = result.scalar_one_or_none() or RiskScore(entity_type="device", entity_id=device.id)
    risk.score = score
    risk.grade = grade
    risk.calculated_at = datetime.now(timezone.utc)

    # Also update the device row for quick access
    device.risk_score = score
    device.risk_grade = grade

    db.add(risk)
    # Append to history (TimescaleDB hypertable)
    db.add(RiskScoreHistory(
        entity_type="device",
        entity_id=device.id,
        score=score,
        grade=grade,
        recorded_at=risk.calculated_at,
    ))
    await db.commit()
    return risk


async def recalculate_all(db: AsyncSession) -> None:
    """Scheduled task: recalculate every device and user score."""
    devices_result = await db.execute(select(Device))
    for device in devices_result.scalars():
        try:
            await recalculate_device(device, db)
        except Exception:
            pass  # one bad device doesn't kill the whole batch


def _days_since(dt: datetime | None) -> int:
    if dt is None:
        return 9999
    tz = dt.tzinfo or timezone.utc
    return (datetime.now(timezone.utc) - dt.replace(tzinfo=tz)).days
