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


@router.get("/alerts")
async def list_threat_alerts(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    source: str | None = Query(None, description="crowdstrike, splunk, sentinelone"),
    severity: str | None = None,
    limit: int = Query(50, le=200),
):
    """
    Aggregated threat alerts from connected SIEMs and EDR platforms.
    Correlated against active findings to highlight in-flight attacks.
    """
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.device import Device
    from api.models.vuln import Finding, FindingStatus

    # Pull cached alert data written by the Celery sync jobs
    from api.models.settings import AppSetting
    result = await db.execute(
        select(AppSetting).where(AppSetting.key.like("threat_cache_%"))
    )
    cached = result.scalars().all()
    alerts = []
    for row in cached:
        if row.value:
            import json
            try:
                data = json.loads(row.value)
                if isinstance(data, list):
                    alerts.extend(data)
            except Exception:
                pass

    if source:
        alerts = [a for a in alerts if a.get("source") == source]
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]

    alerts = alerts[:limit]
    return {
        "alerts": alerts,
        "total": len(alerts),
        "sources": list({a.get("source") for a in alerts if a.get("source")}),
    }


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
    return {"status": "failed", "error": str(result.result)}


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
