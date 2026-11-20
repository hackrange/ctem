"""Cyber Threat module -- cyber role only. Correlates SIEM/EDR data with active CVE findings."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/threat", tags=["threat"])


async def _alerts(db: AsyncSession, key: str | None = None) -> list[dict]:
    """Every cached alert in one shape (or just one by key)."""
    import json
    from api.core.threat_view import normalize
    from api.models.settings import AppSetting

    stmt = select(AppSetting).where(AppSetting.key == key) if key else \
        select(AppSetting).where(AppSetting.key.like("threat\\_alert\\_%", escape="\\")).limit(20000)
    out = []
    for row in (await db.execute(stmt)).scalars():
        try:
            data = json.loads(row.value) if row.value else None
        except ValueError:
            continue
        items = [x for x in (data if isinstance(data, list) else [data]) if isinstance(x, dict)]
        for i, item in enumerate(items):
            out.append(normalize(row.key if len(items) == 1 else f"{row.key}#{i}", item, row.created_at))
    return out


async def _link_devices(db: AsyncSession, alerts: list[dict]) -> None:
    """Point each alert at its CTEM device so the host is clickable."""
    from api.core.device_match import host_key
    from api.models.device import Device

    keys = {host_key(a["hostname"]) for a in alerts if a.get("hostname")} - {None}
    found = {}
    if keys:
        found = dict((await db.execute(select(Device.host_key, Device.id).where(Device.host_key.in_(keys)))).all())
    for a in alerts:
        a["device_id"] = found.get(host_key(a.get("hostname")))


@router.get("/alerts")
async def list_threat_alerts(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    source: str | None = Query(None, max_length=64, description="Source name or code: crowdstrike / CS"),
    severity: str | None = Query(None, max_length=32),
    status: str | None = Query(None, max_length=32),
    sort: str = Query("severity", max_length=32),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Threat alerts from connected EDR, SIEM and firewall tools; worst first by default."""
    from api.core.threat_view import SORTS, matches, sort_key

    alerts = await _alerts(db)
    sources = sorted({(a["source"], a["source_code"]) for a in alerts if a["source"]}, key=lambda s: s[1])
    statuses = sorted({a["status"] for a in alerts if a["status"]})
    if source:
        s = source.strip().lower()
        alerts = [a for a in alerts if s in ((a["source"] or ""), a["source_code"].lower())]
    if severity:
        alerts = [a for a in alerts if (a["severity"] or "") == severity.strip().lower()]
    if status:
        alerts = [a for a in alerts if (a["status"] or "") == status.strip().lower()]
    if q and q.strip():
        alerts = [a for a in alerts if matches(a, q.strip())]
    alerts.sort(key=sort_key(sort if sort in SORTS else "severity"), reverse=order == "desc")
    page = alerts[offset:offset + limit]
    await _link_devices(db, page)
    return {"alerts": page, "total": len(alerts), "limit": limit, "offset": offset,
            "sources": [{"source": s, "code": c} for s, c in sources], "statuses": statuses}


@router.get("/alerts/detail")
async def get_threat_alert(
    id: str = Query(..., min_length=14, max_length=300, pattern=r"^threat_alert_[^#\s]+(#\d{1,4})?$"),
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    key = id.partition("#")[0]
    found = [a for a in await _alerts(db, key) if a["id"] == id]
    if not found:
        raise HTTPException(404, detail="Alert not found")
    await _link_devices(db, found)
    alert = found[0]
    detail = await _detail(db, key) if alert.get("has_detail") else {}
    related = await _related(db, alert)
    from api.core.threat_timeline import actions_text, story, timeline
    return {**alert, "detail": detail, "story": story(alert, detail) if detail else None,
            "actions_text": actions_text(detail) if detail else [],
            "timeline": timeline(alert, detail, related), "related": related,
            "ctem_device": await _ctem_device(db, alert.get("device_id"))}


async def _detail(db: AsyncSession, key: str) -> dict:
    """The encrypted detail, opened and rebuilt from known keys again (it came from outside)."""
    import json
    import logging

    from api.core.cs_alert import csa
    from api.core.encryption import decrypt
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    try:
        raw = json.loads(row.value) if row and row.value else {}
        return csa.clean(json.loads(decrypt(raw["detail_enc"]))) if isinstance(raw, dict) and raw.get("detail_enc") else {}
    except Exception:  # noqa: BLE001 -- a bad row shows the alert without its detail
        logging.getLogger("open-ctem.threat").warning("alert detail unreadable for %s", key[:80])
        return {}


async def _related(db: AsyncSession, alert: dict, days: int = 7) -> list[dict]:
    """Other alerts on the same host within a week either side (or from the same process tree)."""
    from datetime import timedelta
    host, agg = (alert.get("hostname") or "").lower(), alert.get("aggregate_id")
    try:
        at = datetime.fromisoformat(alert["detected_at"]) if alert.get("detected_at") else None
    except ValueError:
        at = None
    out = []
    for a in await _alerts(db):
        if a["id"] == alert["id"]:
            continue
        same = (agg and a.get("aggregate_id") == agg) or (host and (a.get("hostname") or "").lower() == host)
        if not same:
            continue
        if at and a.get("detected_at") and not (agg and a.get("aggregate_id") == agg):
            try:
                if abs(datetime.fromisoformat(a["detected_at"]) - at) > timedelta(days=days):
                    continue
            except (ValueError, TypeError):   # unparseable, or one side has no time zone
                continue
        out.append({k: a.get(k) for k in ("id", "title", "severity", "status", "detected_at", "technique_id",
                                          "source_code")})
    out.sort(key=lambda r: r.get("detected_at") or "")
    return out[:25]


async def _ctem_device(db: AsyncSession, device_id: str | None) -> dict | None:
    """What CTEM knows about the host: risk, open and KEV findings, who it's assigned to."""
    if not device_id:
        return None
    from api.models.device import Device
    from api.routes import device_query as dq
    d = (await db.execute(dq.with_relations(select(Device).where(Device.id == device_id)))).scalars().first()
    if d is None:
        return None
    a = dq.assigned_user(d)
    return {"id": str(d.id), "risk_grade": d.risk_grade.value if d.risk_grade else None, "risk_score": d.risk_score,
            "open_findings": d.open_findings or 0, "kev_findings": d.kev_findings or 0, "criticality": d.criticality,
            "assigned_to": a["name"] if a else None, "user": dq.user_label(d), "edr_contained": bool(d.edr_contained),
            "internet_exposed": bool(d.is_internet_exposed), "device_type": d.device_type.value if d.device_type else None}


@router.post("/analyze")
async def ai_analyze_threat(
    body: ThreatAnalysisRequest,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Queue AI analysis of a set of alert IDs against active CVE findings.
    Returns immediately with a task ID; result is available at /threat/analysis/{task_id}.
    AI runs async via Celery to avoid blocking and to batch token usage efficiently.
    """
    from api.core.tasks import analyze_threat_alerts
    task = analyze_threat_alerts.delay(body.alert_ids, body.device_id)
    return {"task_id": task.id, "status": "queued", "message": "AI analysis queued. Check back in ~30 seconds."}


@router.get("/analysis/{task_id}")
async def get_analysis_result(
    task_id: str,
    _: User = Depends(require_cyber_or_admin),
):
    """Poll for the result of an AI threat analysis task."""
    from api.core.tasks import celery_app
    result = celery_app.AsyncResult(task_id)
    if result.state == "PENDING":
        return {"status": "pending"}
    if result.state == "SUCCESS":
        return {"status": "complete", "result": result.result}
    if result.state in ("STARTED", "RETRY", "RECEIVED"):
        return {"status": "running"}
    return {"status": "failed", "error": "Analysis failed"}


@router.post("/push-to-siem")
async def push_to_siem(
    body: SIEMPushRequest,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Push enriched risk context back to Splunk (or other configured SIEMs).
    Uses the SSRF-safe httpx client -- no internal IP targets allowed.
    """
    from api.core.tasks import push_siem_context
    task = push_siem_context.delay(body.target_integration_id, body.payload)
    return {"task_id": task.id, "status": "queued"}


class ThreatAnalysisRequest(BaseModel):
    alert_ids: list[str]
    device_id: str | None = None
    context: str | None = None     # optional freeform context for the AI prompt


class SIEMPushRequest(BaseModel):
    target_integration_id: str
    payload: dict
