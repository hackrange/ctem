"""Celery tasks for async integration syncs, scoring, and AI analysis."""
from __future__ import annotations

import asyncio
import json
import logging

from celery import Celery
from celery.signals import worker_process_init

from api.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "open-ctem",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_expires=86400,
    worker_hijack_root_logger=False,
    beat_schedule={
        "check-pending-syncs": {
            "task": "api.core.tasks.check_pending_syncs",
            "schedule": 300.0,
        },
        "recalculate-all-risk-scores": {
            # Full pass daily (offline-days and enrichment drift); syncs rescore what they change
            "task": "api.core.tasks.recalculate_all_risk_scores",
            "schedule": 86400.0,
        },
        "enrich-threat-intel": {
            "task": "api.core.tasks.enrich_threat_intel",
            "schedule": 86400.0,
        },
        "hunt-watch": {
            "task": "api.core.tasks.hunt_watch",
            "schedule": 3600.0,
        },
        # Daily run of every control check so GRC evidence history has no gaps
        "grc-checks": {
            "task": "api.core.tasks.run_grc_checks",
            "schedule": 86400.0,
        },
        # The vulnerability dashboard's unfiltered view takes ~15s to build; keep it ready
        "warm-vuln-dashboard": {
            "task": "api.core.tasks.warm_vuln_dashboard",
            "schedule": 900.0,
        },
        # Admin > Utilization: a row a minute, rolled into hours
        # Stale AD counts for dashboard trends (today's row is overwritten, so hourly keeps it current)
        "record-snapshots": {
            "task": "api.core.tasks.record_snapshots",
            "schedule": 3600.0,
        },
        "record-utilization": {
            "task": "api.core.tasks.record_utilization",
            "schedule": 60.0,
            "options": {"expires": 55},
        },
    },
)

log = logging.getLogger("open-ctem.tasks")


@worker_process_init.connect
def _init_worker(**kwargs):
    from api.core.db import init_db_worker
    init_db_worker()


@celery_app.task(name="api.core.tasks.check_pending_syncs")
def check_pending_syncs():
    asyncio.run(_check_pending_syncs())


async def _check_pending_syncs():
    from api.core.db import get_session
    from api.integrations.base import run_due_syncs
    async for db in get_session():
        await run_due_syncs(db)


@celery_app.task(name="api.core.tasks.recalculate_all_risk_scores")
def recalculate_all_risk_scores():
    asyncio.run(_recalculate_all())


@celery_app.task(name="api.core.tasks.warm_vuln_dashboard", time_limit=600, soft_time_limit=540)
def warm_vuln_dashboard():
    asyncio.run(_warm_vuln_dashboard())


async def _warm_vuln_dashboard():
    from api.core.db import get_session
    from api.core.vuln_dashboard import cached
    async for db in get_session():
        await cached(db, "90d", None, None, fresh=True)


async def _recalculate_all():
    from api.core.db import get_session
    from api.scoring.engine import recalculate_all
    async for db in get_session():
        await recalculate_all(db)


@celery_app.task(name="api.core.tasks.sync_integration")
def sync_integration(integration_id: str):
    asyncio.run(_sync_integration(integration_id))


async def _sync_integration(integration_id: str):
    from datetime import datetime, timezone

    from api.core.db import get_session
    from api.integrations.base import sync_by_id
    started = datetime.now(timezone.utc)
    async for db in get_session():
        ok = await sync_by_id(db, integration_id)
    if ok:
        # Score what this sync changed now, not on the next daily pass
        post_sync_pipeline.delay(started.isoformat())


@celery_app.task(name="api.core.tasks.enrich_threat_intel")
def enrich_threat_intel():
    asyncio.run(_enrich())


async def _enrich():
    from api.core.config import get_settings
    from api.core.db import get_session
    from api.enrichment.kev_epss import enrich
    if not get_settings().threat_feeds_enabled:
        return None
    async for db in get_session():
        return await enrich(db)


@celery_app.task(name="api.core.tasks.post_sync_pipeline")
def post_sync_pipeline(since: str | None = None):
    # Enrichment first so the scores see fresh KEV/EPSS data
    asyncio.run(_enrich())
    asyncio.run(_recalculate_changed(since) if since else _recalculate_all())


async def _recalculate_changed(since: str):
    from datetime import datetime

    from api.core.db import get_session
    from api.scoring.engine import recalculate_changed
    async for db in get_session():
        await recalculate_changed(db, datetime.fromisoformat(since))


@celery_app.task(name="api.core.tasks.analyze_threat_alerts")
def analyze_threat_alerts(alert_ids: list[str], device_id: str | None = None) -> dict:
    """
    AI-assisted threat analysis. Only called when AI integration is configured.
    Batches alert data into a single LLM call to minimize token usage.
    Result is cached in Redis for 24h so identical queries don't re-run.
    """
    return asyncio.run(_ai_analyze(alert_ids, device_id))


async def _ai_analyze(alert_ids: list[str], device_id: str | None) -> dict:
    cfg = get_settings()
    cache_key = f"ai_analysis:{':'.join(sorted(alert_ids))}"
    # Check Redis cache first
    import redis
    r = redis.from_url(cfg.redis_url)
    cached = r.get(cache_key)
    if cached:
        return json.loads(cached)

    from api.core.db import get_session
    from api.models.settings import AppSetting
    from sqlalchemy import select

    from api.hunt.ai import get_ai

    alert_data = []
    ai = None
    async for db in get_session():
        ai = await get_ai(db)   # whichever AI integration is enabled: Anthropic, Bedrock, OpenAI, custom
        if ai is None:
            return {"error": "AI integration not configured"}
        for aid in alert_ids[:50]:  # cap to avoid runaway tokens
            result = await db.execute(
                select(AppSetting).where(AppSetting.key == f"threat_alert_{aid}")
            )
            row = result.scalar_one_or_none()
            if row and row.value:
                try:
                    a = json.loads(row.value)
                    if isinstance(a, dict):
                        a.pop("detail_enc", None)   # command lines and users don't go to the AI provider
                    alert_data.append(a)
                except ValueError:
                    log.warning("skipping unreadable alert %s", aid)

    if not alert_data:
        return {"findings": [], "message": "No alert data found for given IDs"}

    prompt = _build_ai_prompt(alert_data, device_id)
    result = await _call_ai(ai, prompt)

    # Cache for 24h (not failures, so a retry after fixing the integration works)
    if "error" not in result:
        r.setex(cache_key, 86400, json.dumps(result))
    return result


@celery_app.task(name="api.core.tasks.hunt_investigate", bind=True, time_limit=600, soft_time_limit=540)
def hunt_investigate(self, question: str, time_range: str) -> dict:
    def progress(stage: str):
        self.update_state(state="PROGRESS", meta={"stage": stage})
    return asyncio.run(_hunt(question, time_range, progress))


async def _hunt(question: str, time_range: str, progress) -> dict:
    from api.core.db import get_session
    from api.hunt.engine import investigate
    async for db in get_session():
        return await investigate(db, question, time_range, progress)


@celery_app.task(name="api.core.tasks.hunt_watch", time_limit=900)
def hunt_watch() -> dict:
    return asyncio.run(_watch())


async def _watch() -> dict:
    from api.core.db import get_session
    from api.hunt.watch import run_watch
    async for db in get_session():
        watch = await run_watch(db)
        return {"issues": len(watch["result"]["issues"])}


@celery_app.task(name="api.core.tasks.run_grc_checks", time_limit=1800)
def run_grc_checks() -> dict:
    return asyncio.run(_grc_checks())


async def _grc_checks() -> dict:
    from api.core.db import get_session
    from api.grc.evidence import run_all
    async for db in get_session():
        return await run_all(db)


@celery_app.task(name="api.core.tasks.hunt_profile", time_limit=300)
def hunt_profile(kind: str, value: str, time_range: str, around: dict | None = None) -> dict:
    return asyncio.run(_profile(kind, value, time_range, around))


async def _profile(kind: str, value: str, time_range: str, around: dict | None) -> dict:
    from api.core.db import get_session
    from api.hunt import profile
    from api.hunt.ai import get_ai
    from api.hunt.engine import _enabled
    from api.hunt.schema import load_schema
    from api.hunt.spl_guard import TIME_RANGES
    from api.integrations.base import get_connector
    async for db in get_session():
        cfg = (await _enabled(db, ["splunk"], live=True) or [None])[0]
        splunk = get_connector("splunk", cfg.config) if cfg else None
        prof = await profile.build(db, kind, value, TIME_RANGES.get(time_range, "-7d"), around,
                                   splunk, await load_schema(db), await get_ai(db))
        return {"mode": "profile", "profile": prof}


@celery_app.task(name="api.core.tasks.hunt_run_search", time_limit=180)
def hunt_run_search(spl: str, time_range: str) -> dict:
    return asyncio.run(_run_one(spl, time_range))


async def _run_one(spl: str, time_range: str) -> dict:
    from api.core.db import get_session
    from api.hunt.engine import _enabled, _run
    from api.hunt.results import for_ui
    from api.hunt.spl_guard import TIME_RANGES, vet_spl
    from api.integrations.base import get_connector
    async for db in get_session():
        cfg = (await _enabled(db, ["splunk"], live=True) or [None])[0]
        if cfg is None:
            return {"mode": "search", "lookups": [], "notes": ["Splunk is not connected."]}
        lk = {"source": "splunk", "title": "Your search", "why": "", "spl": vet_spl(spl)}
        rows = await _run(db, get_connector("splunk", cfg.config), [lk], TIME_RANGES.get(time_range, "-7d"))
        return {"mode": "search", "lookups": for_ui(rows), "notes": []}


def _build_ai_prompt(alerts: list[dict], device_id: str | None) -> str:
    summary = json.dumps(alerts, indent=2)[:8000]  # hard cap on input
    return (
        "You are a threat analyst reviewing security alerts. "
        "Analyze the following alerts and identify: "
        "1. Likely attack techniques (MITRE ATT&CK), "
        "2. Whether these suggest an active compromise, "
        "3. Recommended immediate actions. "
        "Be concise. Flag critical findings first.\n\n"
        f"Alerts:\n{summary}"
    )


async def _call_ai(ai, prompt: str) -> dict:
    """One analysis call through the shared connector (rate limit, monthly budget, metering)."""
    from api.core import ai_usage
    try:
        text = await ai.complete(prompt, max_tokens=1024, timeout=60.0, retries=2, purpose="threat_analysis")
    except ai_usage.AIBudgetExceeded as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 -- logged; the caller only sees a generic reason
        log.warning("threat analysis AI call failed: %s", type(exc).__name__)
        return {"error": "The AI provider could not complete the analysis"}
    return {"analysis": text, "model": ai.config.get("model") or None}


@celery_app.task(name="api.core.tasks.push_siem_context")
def push_siem_context(integration_id: str, payload: dict):
    asyncio.run(_push_siem(integration_id, payload))


async def _push_siem(integration_id: str, payload: dict):
    from api.core.db import get_session
    from api.models.integration import IntegrationConfig
    from sqlalchemy import select
    import uuid as _uuid

    async for db in get_session():
        result = await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.id == str(integration_id))
        )
        cfg = result.scalar_one_or_none()
        if not cfg or not cfg.config:
            return
        endpoint = (cfg.config or {}).get("webhook_url")
        if not endpoint:
            return
        from api.core.ssrf import safe_client
        async with safe_client() as client:
            await client.post(endpoint, json=payload, timeout=15.0)


@celery_app.task(name="api.core.tasks.record_utilization", ignore_result=True)
def record_utilization():
    asyncio.run(_record_utilization())


async def _record_utilization():
    from api.core.db import get_session
    from api.core.utilization import record
    async for db in get_session():
        await record(db)


@celery_app.task(name="api.core.tasks.record_snapshots", ignore_result=True)
def record_snapshots():
    asyncio.run(_record_snapshots())


async def _record_snapshots():
    from api.core.db import get_session
    from api.dashboards import snapshots
    from api.dashboards.m_directory import record_snapshots as rec
    async for db in get_session():
        await rec(db)
        await snapshots.record(db)
