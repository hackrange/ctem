"""High-fidelity alerts for a SIEM: few, specific, and each raised once, so SOAR playbooks can act on them.

Raised every 15 minutes from what CTEM already knows:
- kev_exposed: an open known-exploited (CISA KEV) finding on an internet-facing asset
- edr_alert: a high or critical EDR alert (Falcon endpoint, identity and the rest)
- unauthorized_software: software marked unauthorized newly reported on an asset
- control_failed: a CTEM control check that was passing (or new) and now fails
- intel_match: endpoint telemetry matching a high-confidence threat intel indicator (api/core/hunt_ingest.py)
- rtr_session: a remote response session opened on a host from the EDR's console
Delivered to Splunk HEC directly (api/core/alert_delivery.py) and through the shipper (its local HEC, or a file a
Universal Forwarder reads). Each event carries a stable key, so a playbook can dedupe on it too."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

KINDS = ("kev_exposed", "edr_alert", "unauthorized_software", "control_failed", "intel_match", "rtr_session")
KEEP_DAYS = 30
LOOKBACK = timedelta(days=2)   # how far back a first run looks, so turning it on doesn't replay history


async def _add(db, have: set, key: str, kind: str, severity: str, title: str, body: dict) -> int:
    from api.models.alert_feed import FeedAlert
    if key in have:
        return 0
    have.add(key)
    now = datetime.now(timezone.utc)
    db.add(FeedAlert(key=key[:200], kind=kind, severity=severity, title=title[:300], created_at=now,
                     event={"kind": kind, "severity": severity, "title": title[:300], "key": key[:200],
                            "raised_at": now.isoformat(), **body}))
    return 1


async def existing(db: AsyncSession, keys) -> set:
    """Which of these alert keys are already raised (so an upload that repeats one doesn't raise it twice)."""
    from api.models.alert_feed import FeedAlert
    keys = [k[:200] for k in keys]
    return set((await db.execute(select(FeedAlert.key).where(FeedAlert.key.in_(keys)))).scalars()) if keys else set()


async def raise_new(db: AsyncSession) -> int:
    from api.models.alert_feed import FeedAlert
    since = datetime.now(timezone.utc) - LOOKBACK
    have = set((await db.execute(select(FeedAlert.key).where(FeedAlert.created_at >= since - timedelta(days=KEEP_DAYS)))).scalars())
    n = await _kev_exposed(db, have, since) + await _edr_alerts(db, have, since) + await _unauthorized(db, have, since)
    n += await _controls(db, have, since)
    await db.commit()
    return n


def _asset(d) -> dict:
    return {"asset_id": str(d.id), "hostname": d.hostname, "asset_type": d.device_type.value if d.device_type else None,
            "criticality": d.criticality, "risk_grade": d.risk_grade.value if d.risk_grade else None}


async def _kev_exposed(db, have, since) -> int:
    from api.models.device import Device
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    rows = (await db.execute(select(Finding, Vulnerability, Device).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                             .join(Device, Device.id == Finding.device_id)
                             .where(Finding.status == FindingStatus.open, Vulnerability.is_kev == True,  # noqa: E712
                                    Device.is_internet_exposed == True, Device.scope_exempt_until.is_(None))  # noqa: E712
                             .limit(5000))).all()
    n = 0
    for f, v, d in rows:
        n += await _add(db, have, f"kev_exposed:{d.id}:{v.cve_id or v.id}", "kev_exposed", "critical",
                        f"Known-exploited {v.cve_id or v.title} open on internet-facing {d.hostname}",
                        {**_asset(d), "cve": v.cve_id, "vulnerability": v.title, "cvss": v.cvss_base, "source": f.source,
                         "first_detected": f.first_detected.isoformat() if f.first_detected else None})
    return n


async def _edr_alerts(db, have, since) -> int:
    from api.models.settings import AppSetting
    from api.core.alert_allow import accepted_keys
    n = 0
    rows = list((await db.execute(select(AppSetting).where(AppSetting.key.like("threat\\_alert\\_%", escape="\\"),
                                                           AppSetting.updated_at >= since.replace(tzinfo=None)))).scalars())
    parsed = []
    for row in rows:
        try:
            parsed.append((row.key, json.loads(row.value or "{}")))
        except ValueError:
            continue
    gone = await accepted_keys(db, parsed)   # accepted alerts (the allow list) aren't sent to the SIEM
    for key, a in parsed:
        if key in gone or not isinstance(a, dict):
            continue
        sev = str(a.get("severity") or "").lower()
        if sev not in ("high", "critical"):
            continue
        n += await _add(db, have, f"edr_alert:{a.get('id')}", "edr_alert", sev,
                        f"{a.get('source') or 'EDR'} {sev} alert on {a.get('hostname') or 'a host'}: {a.get('title') or ''}",
                        {"hostname": a.get("hostname"), "source": a.get("source"), "alert_id": a.get("id"), "status": a.get("status"),
                         "tactic": a.get("tactic"), "technique": a.get("technique"), "technique_id": a.get("technique_id"),
                         "detected_at": a.get("detected_at"), "link": a.get("link")})
    return n


async def _unauthorized(db, have, since) -> int:
    from api.core.software_status import unauthorized_here
    from api.models.device import Device
    from api.models.software import SoftwareInstall, SoftwareTitle
    rows = (await db.execute(select(SoftwareInstall, SoftwareTitle, Device).join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id)
                             .join(Device, Device.id == SoftwareInstall.device_id)
                             .where(SoftwareInstall.first_seen >= since, unauthorized_here()).limit(5000))).all()
    n = 0
    for i, t, d in rows:
        n += await _add(db, have, f"unauthorized_software:{d.id}:{t.id}", "unauthorized_software", "high",
                        f"Unauthorized software {t.title} on {d.hostname}",
                        {**_asset(d), "software": t.title, "vendor": t.vendor, "version": i.version, "sha256": i.sha256,
                         "source": i.source, "why": t.status_note})
    return n


async def _controls(db, have, since) -> int:
    from api.grc.checks import REGISTRY
    from api.models.grc import GrcCheckResult
    n = 0
    for check_type in REGISTRY:
        two = (await db.execute(select(GrcCheckResult).where(GrcCheckResult.check_type == check_type)
                                .order_by(GrcCheckResult.measured_at.desc()).limit(2))).scalars().all()
        if not two or two[0].result != "fail" or two[0].measured_at < since or (len(two) > 1 and two[1].result == "fail"):
            continue
        r = two[0]
        n += await _add(db, have, f"control_failed:{check_type}:{r.measured_at.date().isoformat()}", "control_failed", "high",
                        f"CTEM control check failed: {REGISTRY[check_type].name}",
                        {"check": check_type, "summary": r.summary, "measured_at": r.measured_at.isoformat()})
    return n


async def prune(db: AsyncSession) -> int:
    from sqlalchemy import delete

    from api.models.alert_feed import FeedAlert
    r = await db.execute(delete(FeedAlert).where(FeedAlert.created_at < datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)))
    await db.commit()
    return r.rowcount or 0


async def after(db: AsyncSession, seq: int, limit: int = 500) -> list:
    from api.models.alert_feed import FeedAlert
    return (await db.execute(select(FeedAlert).where(FeedAlert.seq > seq).order_by(FeedAlert.seq).limit(limit))).scalars().all()


async def latest_seq(db: AsyncSession) -> int:
    from api.models.alert_feed import FeedAlert
    return (await db.execute(select(func.coalesce(func.max(FeedAlert.seq), 0)))).scalar_one()
