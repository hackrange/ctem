"""Hunt module -- AI-driven cross-tool telemetry investigation. Cyber role only."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.core.ssrf import safe_client
from api.models.user import User

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])


@router.post("/query")
async def hunt_query(
    body: HuntQueryRequest,
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Natural language hunt query. If AI is enabled, fan out searches across all
    available telemetry sources and use AI to synthesize the answer.
    Example: "server001 users reporting xyz webservice is down, what's wrong?"
    """
    from api.core.config import get_settings
    settings = get_settings()

    telemetry = await _gather_telemetry(body.query, body.asset_hint, db)

    if settings.ai_api_key:
        task_id = await _queue_ai_hunt(body.query, telemetry, settings)
        return {
            "mode": "ai",
            "task_id": task_id,
            "telemetry_sources": list(telemetry.keys()),
            "telemetry_count": sum(len(v) for v in telemetry.values()),
            "message": "AI analysis queued. Poll /hunt/result/{task_id} for results.",
        }
    else:
        # No AI -- return raw aggregated telemetry ranked by severity
        return {
            "mode": "keyword",
            "results": _keyword_results(body.query, telemetry),
            "telemetry_sources": list(telemetry.keys()),
        }


@router.get("/result/{task_id}")
async def hunt_result(
    task_id: str,
    _: User = Depends(require_cyber_or_admin),
):
    """Poll for the result of an AI hunt analysis task."""
    from api.core.tasks import celery_app
    result = celery_app.AsyncResult(task_id)
    if result.state == "PENDING":
        return {"status": "pending"}
    if result.state == "SUCCESS":
        return {"status": "complete", "result": result.result}
    if result.state in ("STARTED", "RETRY", "RECEIVED"):
        return {"status": "running"}
    return {"status": "failed", "error": "Analysis failed"}


@router.get("/splunk/catalog")
async def get_spl_catalog(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Return pre-built SPL searches generated from Splunk index introspection.
    SOC team can browse, copy, and run these directly in Splunk.
    """
    from api.models.settings import AppSetting
    result = await db.execute(
        select(AppSetting).where(AppSetting.key == "splunk_spl_catalog")
    )
    row = result.scalar_one_or_none()
    if row is None or not row.value:
        return {"catalog": [], "message": "No SPL catalog yet -- trigger a Splunk sync to generate one"}
    try:
        catalog = json.loads(row.value)
    except Exception:
        catalog = []
    return {"catalog": catalog, "generated_at": row.updated_at.isoformat() if row.updated_at else None}


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _gather_telemetry(query: str, asset_hint: str | None, db: AsyncSession) -> dict[str, list]:
    """Fan out keyword searches across all cached telemetry in the DB."""
    from api.models.settings import AppSetting
    from sqlalchemy import or_

    keywords = _extract_keywords(query, asset_hint)
    result = await db.execute(
        select(AppSetting).where(
            AppSetting.key.like("threat_alert_%") | AppSetting.key.like("splunk_event_%")
        ).limit(2000)
    )
    rows = result.scalars().all()

    telemetry: dict[str, list] = {}
    for row in rows:
        if not row.value:
            continue
        try:
            item = json.loads(row.value)
        except Exception:
            continue
        # Match by keyword
        item_text = json.dumps(item).lower()
        if any(kw.lower() in item_text for kw in keywords):
            source = item.get("source", "unknown")
            telemetry.setdefault(source, []).append(item)

    return telemetry


def _extract_keywords(query: str, asset_hint: str | None) -> list[str]:
    words = query.lower().split()
    # Remove common filler words
    stop = {"is", "are", "the", "a", "an", "and", "or", "what", "why", "how",
            "can", "be", "has", "have", "had", "i", "we", "our", "it", "this"}
    keywords = [w.strip(".,?!") for w in words if w not in stop and len(w) > 2]
    if asset_hint:
        keywords.insert(0, asset_hint)
    return keywords[:15]  # cap to avoid performance issues


def _keyword_results(query: str, telemetry: dict[str, list]) -> list[dict]:
    """Flatten and sort telemetry by severity for no-AI mode."""
    _severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
    results = []
    for source, items in telemetry.items():
        for item in items:
            results.append({**item, "_source": source})
    results.sort(key=lambda x: _severity_order.get(str(x.get("severity", "")).lower(), 5))
    return results[:50]


async def _queue_ai_hunt(query: str, telemetry: dict, settings) -> str:
    from api.core.tasks import ai_hunt_query
    task = ai_hunt_query.delay(query, telemetry)
    return task.id


class HuntQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    asset_hint: str | None = Field(None, max_length=255)   # hostname/IP to anchor the search
    max_results: int = Field(50, ge=1, le=500)
