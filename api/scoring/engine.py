"""Scoring orchestrator. Recalculates risk for all devices and users."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.models.device import Device, RiskGrade
from api.models.risk import RiskScore, RiskScoreHistory
from api.models.vuln import Finding, FindingStatus
from api.scoring.compensating import ControlContext, port_closed_note
from api.scoring import cloud_score
from api.scoring.device_score import compute_device_score, device_grade, score_finding
from api.scoring.user_score import compute_user_score

log = logging.getLogger("open-ctem.scoring")


async def _app_scores(device: Device, findings: list, db: AsyncSession) -> tuple[float, str, list, str]:
    """Code (repository) and Web app (site) scoring: see api.scoring.app_score. Returns score, grade, per-finding
    (score, grade) and the breakdown kept with the score."""
    from api.core import tag_roles
    from api.models.device import DeviceTag
    from api.models.tag import Tag
    from api.scoring import app_score
    names = [n for (n,) in (await db.execute(select(Tag.name).join(DeviceTag, DeviceTag.tag_id == Tag.id)
                                             .where(DeviceTag.device_id == device.id))).all()]
    env = tag_roles.values(names, "environment")
    holds = sorted({h for f in findings for h in ((f.details or {}).get("asset") or {}).get("holds", [])})
    holds += [n.split(":", 1)[1] for n in names if n.lower().startswith("gcr:") and any(k in n.lower() for k in app_score.SENSITIVE)]
    kind = "web" if device.device_type.value == "website" else "code"
    crit = app_score.impact(device.criticality, holds, env)
    expo = app_score.exposure(kind, bool(device.is_internet_exposed))
    per, reasons = [], {}
    for f in findings:
        v = f.vuln
        sc, why = app_score.score_finding((v.cvss_base or 0.0) if v else 0.0, (v.epss_score or 0.0) if v else 0.0,
                                          bool(v and v.is_kev), f.details or {}, kind, crit, expo)
        per.append((sc, device_grade(sc), why))
        reasons[sc] = why
    score, why = app_score.roll_up([p[0] for p in per])
    worst = max(reasons) if reasons else None
    breakdown = json.dumps({"model": kind, "why": why, "worst": reasons.get(worst, []), "impact": crit[1], "exposure": expo[1]})[:1000]
    return score, device_grade(score), per, breakdown


async def _edr_facts(device: Device, db: AsyncSession) -> dict:
    """What the EDR's policies do on this host, once per host (api/scoring/edr_controls.py)."""
    from api.scoring import edr_controls as ec
    if not device.edr_active or not device.edr_vendor:
        return {}
    rows = await ec.policies(db)
    get = lambda pid, kind: rows.get((device.edr_vendor, pid, kind)) if pid else None  # noqa: E731
    return {"prevention": ec.prevention(get(device.edr_prevention_policy, "prevention")),
            "firewall": get(device.edr_firewall_policy, "firewall"), "usb_blocked": device.usb_storage_blocked}


def _edr_context(edr: dict, f) -> dict:
    """The ControlContext fields for one finding on that host."""
    from api.scoring import edr_controls as ec
    if not edr:
        return {}
    fw = ec.firewall(edr["firewall"], f.ports) if f.exposure == "listening" else None
    return {"edr_prevention": edr["prevention"], "usb_blocked": edr["usb_blocked"],
            "memory_flaw": _memory_flaw(f.vuln), "host_firewall": fw}


_FLAW: dict = {}


def _memory_flaw(v) -> bool:
    """Is the flaw memory corruption (what exploit mitigations target)? Once per vulnerability, not once per host:
    a CVE on 3,000 hosts used to be read 3,000 times."""
    from api.scoring import edr_controls as ec
    if v is None:
        return False
    key = (v.id, hash(v.title), hash(v.description))   # an edited description is checked again
    hit = _FLAW.get(key)
    if hit is None:
        if len(_FLAW) > 200_000:
            _FLAW.clear()
        hit = _FLAW[key] = bool(ec.MEMORY_FLAW.search(f"{v.title or ''} {v.description or ''}"[:4000]))
    return hit


async def recalculate_device(device: Device, db: AsyncSession) -> RiskScore:
    """Recalculate and persist the risk score for a single device (a repository or a site by their own model).
    Its own writes (scores, each finding's reason) are not input changes: they mark nothing for rescoring."""
    from api.scoring.dirty import QUIET
    info = db.sync_session.info
    was, info[QUIET] = info.get(QUIET), True
    try:
        return await _recalculate_device(device, db)
    finally:
        info[QUIET] = was


async def _recalculate_device(device: Device, db: AsyncSession) -> RiskScore:
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
    from api.cloud.exposure import for_device
    cloud = await for_device(db, device.id)
    cloud_ports = [p for a in cloud for p in a["ports"]] if cloud else None   # None: not a cloud instance
    findings_data = []
    days_offline = _days_since(device.last_seen)
    edr = await _edr_facts(device, db)
    for f in findings:
        ctx = ControlContext(
            edr_active=device.edr_active,
            edr_vendor=device.edr_vendor,
            is_internet_exposed=device.is_internet_exposed,
            device_offline_days=days_offline,
            nodezero_confirmed_exploitable=bool(f.is_reachable and f.reachability_source == "horizon3"),
            nodezero_confirmed_not_exploitable=bool(f.is_reachable is False and f.reachability_source == "horizon3"),
            attack_vector=f.vuln.attack_vector if f.vuln else None,
            exposure=f.exposure, ports=f.ports, cloud_ports=cloud_ports,
            threat_actors=(f.vuln.threat_actors or None) if f.vuln else None,
            port_closed=port_closed_note(f),
            **_edr_context(edr, f),
        )
        findings_data.append({
            "cvss_base": f.vuln.cvss_base or 0.0,
            "epss_score": f.vuln.epss_score or 0.0,
            "is_kev": f.vuln.is_kev,
            "asset_criticality": _CRITICALITY.get(device.criticality or "",
                                                  0.7 if device.device_type.value == "server" else 0.5),
            "is_reachable": f.is_reachable,
            "control_context": ctx,
            # a cloud configuration check has no CVE, EPSS or KEV: scored by api/scoring/cloud_score.py instead
            **({"cloud": cloud_score.score(f.details, f.vuln.cvss_base if f.vuln else None)} if f.domain == "cloud" else {}),
        })

    app = device.device_type.value in ("code_repository", "website")
    breakdown = None
    if app:
        score, grade, per_finding, breakdown = await _app_scores(device, findings, db)
    else:
        score, grade = compute_device_score(findings_data)
    from api.core.device_scope_exempt import is_exempt
    exempt = is_exempt(device)
    # isolated by the EDR (nothing on it is reachable right now) or marked Not In Scope: nothing counts
    contained = bool(getattr(device, "edr_contained", False)) or exempt
    device.raw_risk_score, device.raw_risk_grade = score, grade
    if contained:
        score, grade = 0.0, "A"

    # Per-finding scores feed the sortable finding lists on the device and vuln pages
    worst = (-1.0, [])
    for i, (f, data) in enumerate(zip(findings, findings_data)):
        if app:
            fs, why = per_finding[i][0], per_finding[i][2]
            f.details = {**(f.details or {}), "score_why": why}   # the reason for this finding's score
        elif "cloud" in data:
            fs, mult = data["cloud"]
            if fs > worst[0]:
                worst = (fs, list(mult))
        else:
            fs, mult = score_finding(
                cvss_base=data["cvss_base"], epss_score=data["epss_score"], is_kev=data["is_kev"],
                asset_criticality=data["asset_criticality"], is_reachable=data["is_reachable"],
                ctx=data["control_context"],
            )
            if fs > worst[0]:
                base = [f"CVSS {data['cvss_base']:.1f}", f"EPSS {data['epss_score'] * 100:.1f}%"]
                base += ["known exploited (KEV)"] if data["is_kev"] else []
                base += [f"asset criticality {data['asset_criticality']:.2f}"]
                worst = (fs, base + list(mult))
        f.raw_score, f.raw_grade = round(fs, 1), device_grade(fs)
        f.composite_score = 0.0 if contained else f.raw_score
        f.risk_grade = "A" if contained else f.raw_grade
    if not app:   # hosts: the score is the average of the worst tenth of their findings
        top = max(1, len(findings) // 10)
        why = ((f"its worst finding (of {len(findings)})" if top == 1 else f"average of its worst {top} of {len(findings)} findings")
               if findings else "no open findings")
        if contained:
            why = "contained by the EDR or not in scope, so nothing counts right now"
        breakdown = json.dumps({"model": "host", "why": why, "worst": worst[1]})[:1000]
    # Contained or Not In Scope: the findings stay stored and shown, but none of them count
    device.open_findings = 0 if contained else len(findings)
    device.kev_findings = 0 if contained else sum(1 for f in findings if f.vuln and f.vuln.is_kev)

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
    risk.score_breakdown = breakdown
    risk.calculated_at = datetime.now(timezone.utc)

    # Also update the device row for quick access
    device.risk_score = score
    device.risk_grade = RiskGrade(grade)

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
    from sqlalchemy import or_

    from api.models.device import Device as DeviceModel
    from api.models.device import DeviceAssignment
    # Assigned machines count for the person they're assigned to; detected ones only when nobody assigned them
    assigned = select(DeviceAssignment.device_id).where(DeviceAssignment.user_id == user_model.id)
    taken = select(DeviceAssignment.device_id).where(DeviceAssignment.user_id.is_not(None))
    dev_result = await db.execute(select(DeviceModel).where(or_(
        DeviceModel.id.in_(assigned),
        (DeviceModel.owner_user_id == user_model.id) & DeviceModel.id.not_in(taken),
    )))
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

    await expire_scope_exemptions(db)
    from api.integrations.pentest_merge import reconcile
    await reconcile(db)   # one finding per CVE per host when the pentest and a scanner both have it
    from api.core.vuln_exceptions import sync_all
    await sync_all(db)   # expire exceptions and cover new findings before scoring
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
    """Rescore only devices where something the score reads changed since `since` (a sync's start): its own inputs
    or its findings' (api/scoring/dirty.py marks them), or a vulnerability it has (a new KEV listing, EPSS)."""
    from sqlalchemy import union

    from api.models.vuln import Vulnerability
    since = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
    changed_vulns = select(Vulnerability.id).where(Vulnerability.score_inputs_at >= since)
    ids_q = union(
        select(Device.id).where(Device.score_inputs_at >= since),
        select(Finding.device_id).where(Finding.vuln_id.in_(changed_vulns),
                                        Finding.status.in_([FindingStatus.open, FindingStatus.in_progress])),
    )
    from api.integrations.pentest_merge import reconcile
    merged = await reconcile(db)   # one finding per CVE per host when the pentest and a scanner both have it
    ids = [r[0] for r in (await db.execute(ids_q)).all()] + sorted(merged)
    ids += await expire_scope_exemptions(db)
    from api.core.vuln_exceptions import sync_all
    ids += await sync_all(db)
    ids = list(dict.fromkeys(ids))
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


async def expire_scope_exemptions(db: AsyncSession) -> list[str]:
    """Not In Scope exclusions whose end date has passed: clear them, audit it, and return the ids to rescore."""
    from api.models.settings import AuditLog
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(Device).where(Device.scope_exempt_until.is_not(None),
                                                  Device.scope_exempt_until <= now))).scalars().all()
    for d in rows:
        db.add(AuditLog(actor_username="system", action="device.scope_expired", resource_type="device",
                        resource_id=str(d.id), detail=f"Not In Scope ended {d.scope_exempt_until.date().isoformat()}"))
        d.scope_exempt_until = d.scope_exempt_reason = d.scope_exempt_by = d.scope_exempt_at = None
    if rows:
        await db.commit()
    return [str(d.id) for d in rows]


async def refresh_affected_counts(db: AsyncSession) -> None:
    """One set-based UPDATE so vuln lists can sort by affected count and age without counting millions of findings."""
    from sqlalchemy import distinct, func, update

    from api.models.vuln import Vulnerability
    from api.core.device_scope_exempt import in_scope_findings
    count = (select(func.count(distinct(Finding.device_id)))
             .where(Finding.vuln_id == Vulnerability.id, in_scope_findings(),
                    Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]))
             .correlate(Vulnerability).scalar_subquery())
    oldest = (select(func.min(Finding.first_detected))
              .where(Finding.vuln_id == Vulnerability.id, in_scope_findings(),
                     Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]))
              .correlate(Vulnerability).scalar_subquery())
    await db.execute(update(Vulnerability).values(affected_devices=count, first_found=oldest)
                     .execution_options(synchronize_session=False))
    await db.commit()


# Scanner-assigned business criticality beats the server/workstation guess
_CRITICALITY = {"Very High": 1.0, "High": 0.85, "Medium": 0.6, "Low": 0.4, "Very Low": 0.25}


def _days_since(dt: datetime | None) -> int:
    if dt is None:
        return 9999
    tz = dt.tzinfo or timezone.utc
    return (datetime.now(timezone.utc) - dt.replace(tzinfo=tz)).days
