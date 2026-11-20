"""Scoring orchestrator. Recalculates risk for all devices and users."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.models.device import Device
from api.models.risk import RiskScore, RiskScoreHistory
from api.models.vuln import Finding, FindingStatus
from api.scoring.compensating import ControlContext
from api.scoring.device_score import compute_device_score, device_grade, score_finding
from api.scoring.user_score import compute_user_score

log = logging.getLogger("open-ctem.scoring")


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
            "asset_criticality": _CRITICALITY.get(device.criticality or "",
                                                  0.7 if device.device_type.value == "server" else 0.5),
            "is_reachable": f.is_reachable,
            "control_context": ctx,
        })

    score, grade = compute_device_score(findings_data)
    contained = bool(getattr(device, "edr_contained", False))
    device.raw_risk_score, device.raw_risk_grade = score, grade
    if contained:
        score, grade = 0.0, "A"  # isolated by the EDR: nothing on it is reachable right now

    # Per-finding scores feed the sortable finding lists on the device and vuln pages
    for f, data in zip(findings, findings_data):
        fs, _ = score_finding(
            cvss_base=data["cvss_base"], epss_score=data["epss_score"], is_kev=data["is_kev"],
            asset_criticality=data["asset_criticality"], is_reachable=data["is_reachable"],
            ctx=data["control_context"],
        )
        f.raw_score, f.raw_grade = round(fs, 1), device_grade(fs)
        f.composite_score = 0.0 if contained else f.raw_score
        f.risk_grade = "A" if contained else f.raw_grade
    device.open_findings = len(findings)
    device.kev_findings = sum(1 for f in findings if f.vuln and f.vuln.is_kev)

    # Upsert the current score
    result = await db.execute(
        select(RiskScore).where(
            RiskScore.entity_type == "device",
            RiskScore.entity_id == device.id,
        )
    )
    risk = result.scalar_one_or_none() or RiskScore(entity_type="device", entity_id=device.id)
    changed = risk.score != score or risk.grade != grade
    risk.score = score
    risk.grade = grade
    risk.calculated_at = datetime.now(timezone.utc)

    # Also update the device row for quick access
    device.risk_score = score
    device.risk_grade = grade

    db.add(risk)
    # History only on change, so frequent post-sync runs don't flood the hypertable
    if changed:
        db.add(RiskScoreHistory(
            entity_type="device",
            entity_id=device.id,
            score=score,
            grade=grade,
            recorded_at=risk.calculated_at,
        ))
    await db.commit()
    return risk


def _ad_state(u) -> dict | None:
    if getattr(u, "ad_disabled", None) is None and getattr(u, "ad_last_logon", None) is None:
        return None  # no directory data for this user
    pwd = getattr(u, "ad_pwd_last_set", None)
    logon = getattr(u, "ad_last_logon", None)
    return {"disabled": bool(u.ad_disabled), "pwd_never_expires": bool(u.ad_pwd_never_expires),
            "pwd_expired": bool(u.ad_pwd_expired), "locked_out": bool(u.ad_locked_out),
            "pwd_age_days": _days_since(pwd) if pwd else None,
            "days_since_logon": _days_since(logon) if logon else None}


async def recalculate_user(user_model, db: AsyncSession) -> RiskScore | None:
    """
    Recalculate risk score for a single user, pulling composite_identity_score
    from IdentityRiskScore (Grip ITDR + posture + shadow SaaS/AI) if available.
    """
    from api.core.encryption import search_hash
    from api.models.identity import IdentityRiskScore

    email = getattr(user_model, "email", None)
    identity_score: float | None = None

    if email:
        try:
            h = search_hash(email.lower())
            id_result = await db.execute(
                select(IdentityRiskScore).where(IdentityRiskScore.user_email_hash == h)
            )
            id_row = id_result.scalar_one_or_none()
            if id_row:
                # Scale 0-100 to 0-5 for user_score's saas_risk_score param
                identity_score = id_row.composite_identity_score / 20.0
        except Exception:
            log.warning("identity score lookup failed; scoring without it", exc_info=True)

    # Gather devices this user owns for blast radius calculation
    from api.models.device import Device as DeviceModel
    dev_result = await db.execute(
        select(DeviceModel).where(DeviceModel.owner_user_id == user_model.id)
    )
    devices = dev_result.scalars().all()
    device_scores = [d.risk_score for d in devices if d.risk_score is not None]

    score, grade, _ = compute_user_score(
        device_scores=device_scores,
        ad_groups=getattr(user_model, "ad_groups", []) or [],
        mfa_enabled=getattr(user_model, "totp_enabled", False),
        is_service_account=getattr(user_model, "is_service_account", False),
        last_login_days_ago=_days_since(getattr(user_model, "last_login", None)),
        saas_risk_score=identity_score,
        ad=_ad_state(user_model),
    )

    result = await db.execute(
        select(RiskScore).where(
            RiskScore.entity_type == "user",
            RiskScore.entity_id == user_model.id,
        )
    )
    risk = result.scalar_one_or_none() or RiskScore(entity_type="user", entity_id=user_model.id)
    risk.score = score
    risk.grade = grade
    risk.calculated_at = datetime.now(timezone.utc)
    db.add(risk)
    db.add(RiskScoreHistory(entity_type="user", entity_id=user_model.id,
                            score=score, grade=grade, recorded_at=risk.calculated_at))
    await db.commit()
    return risk


async def recalculate_all(db: AsyncSession) -> None:
    """Scheduled task: recalculate every device and user score."""
    from api.models.user import User as UserModel

    devices_result = await db.execute(select(Device))
    for device in devices_result.scalars():
        try:
            await recalculate_device(device, db)
        except Exception:
            log.exception("risk recalc failed for device %s", device.id)

    await refresh_affected_counts(db)

    users_result = await db.execute(select(UserModel).where(UserModel.is_active == True))  # noqa: E712
    for user in users_result.scalars():
        try:
            await recalculate_user(user, db)
        except Exception:
            log.exception("risk recalc failed for user %s", user.id)


async def recalculate_changed(db: AsyncSession, since: datetime) -> int:
    """Rescore only devices created, updated, or with findings touched since `since` (a sync's start)."""
    from sqlalchemy import or_, union

    naive = since.astimezone(timezone.utc).replace(tzinfo=None)  # TimestampMixin columns are naive UTC
    ids_q = union(
        select(Finding.device_id).where(or_(Finding.created_at >= naive, Finding.updated_at >= naive)),
        select(Device.id).where(or_(Device.created_at >= naive, Device.updated_at >= naive)),
    )
    ids = [r[0] for r in (await db.execute(ids_q)).all()]
    for i in range(0, len(ids), 500):
        for device in (await db.execute(select(Device).where(Device.id.in_(ids[i:i + 500])))).scalars():
            try:
                await recalculate_device(device, db)
            except Exception:
                log.exception("risk recalc failed for device %s", device.id)
        db.expunge_all()
    await refresh_affected_counts(db)
    log.info("rescored %d changed devices", len(ids))
    return len(ids)


async def refresh_affected_counts(db: AsyncSession) -> None:
    """One set-based UPDATE so vuln lists can sort by affected count without counting millions of findings."""
    from sqlalchemy import distinct, func, update

    from api.models.vuln import Vulnerability
    count = (select(func.count(distinct(Finding.device_id)))
             .where(Finding.vuln_id == Vulnerability.id,
                    Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]))
             .correlate(Vulnerability).scalar_subquery())
    await db.execute(update(Vulnerability).values(affected_devices=count).execution_options(synchronize_session=False))
    await db.commit()


# Scanner-assigned business criticality beats the server/workstation guess
_CRITICALITY = {"Very High": 1.0, "High": 0.85, "Medium": 0.6, "Low": 0.4, "Very Low": 0.25}


def _days_since(dt: datetime | None) -> int:
    if dt is None:
        return 9999
    tz = dt.tzinfo or timezone.utc
    return (datetime.now(timezone.utc) - dt.replace(tzinfo=tz)).days
