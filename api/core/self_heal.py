"""Self-healing for the background work, so a passing problem fixes itself instead of becoming a ticket.

1. A sync that fails for a passing reason retries on its own: a database deadlock, lock timeout or dropped
   connection, or the vendor timing out, rate-limiting (429) or failing (5xx). It runs again after 5, then 15, then
   45 minutes, and the integration card says when ("Retrying automatically at 14:20 UTC, attempt 2 of 3"). A failure
   a person has to fix (401/403, bad credentials, a setting) is never retried in a loop; the card says what's wrong.
   Every connector's sync is an upsert, so running it again is safe.
2. Daily jobs that didn't run (the scheduler was paused or restarting at their time of day) are run as soon as it's
   noticed: each must have finished within its window.

Both run every 5 minutes (tick). Retry plans are kept in the database (app_settings sync_retry.<id>); when each daily
job last ran is kept in Redis (lost on a Redis restart: then the clock starts again, rather than every job at once)."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

from celery.signals import task_success
from sqlalchemy import select

from api.core.tasks import celery_app

log = logging.getLogger("open-ctem.self_heal")

RETRY_MINUTES = (5, 15, 45)
KEY = "sync_retry.{}"
REDISPATCH_AFTER = timedelta(hours=2)   # a retry handed to a worker that never reported back is handed out again
# task name: hours it may go without finishing
DAILY = {"api.core.tasks.recalculate_all_risk_scores": 26, "api.core.tasks.enrich_threat_intel": 26,
         "api.core.tasks_db.db_maintenance": 26, "api.core.tasks_history.finding_history": 26}
RAN = "selfheal:ran:{}"

celery_app.conf.beat_schedule["self-heal"] = {"task": "api.core.self_heal.tick", "schedule": 300.0, "options": {"expires": 280}}

_DB_PASSING = ("deadlock", "could not serialize", "lock timeout", "lock not available", "canceling statement due to lock")
_PERSON = re.compile(r"\b(401|403)\b|unauthori[sz]ed|forbidden|invalid (credentials|token|api key|client)|"
                     r"needs? (the )?(scope|permission)|not configured|is required", re.I)
_PASSING = re.compile(r"\b(answered|http|status) ?(429|5\d\d)\b|timed? ?out|timeout|temporar|rate.?limit|try again|"
                      r"connection (reset|refused|aborted|closed|error)|deadlock|service unavailable|bad gateway", re.I)


def passing(e: BaseException, why: str = "") -> bool:
    """A failure worth retrying on its own (it should pass), not one a person has to fix."""
    from sqlalchemy.exc import InterfaceError, OperationalError, SQLAlchemyError
    text = f"{e} {why}"
    if isinstance(e, InterfaceError):
        return True   # the database connection dropped
    if isinstance(e, SQLAlchemyError):
        low = text.lower()
        return any(w in low for w in _DB_PASSING) or (isinstance(e, OperationalError) and any(
            w in low for w in ("connection", "server closed", "terminating")))
    try:
        import httpx
        if isinstance(e, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)):
            return True
        if isinstance(e, httpx.HTTPStatusError):
            return e.response.status_code == 429 or e.response.status_code >= 500
    except ImportError:
        pass
    if isinstance(e, (TimeoutError, ConnectionError, asyncio.TimeoutError)):
        return True
    if _PERSON.search(text):
        return False
    return bool(_PASSING.search(text))


async def after_sync(db, cfg_id: str, ok: bool, retry: bool) -> str | None:
    """Plan, or clear, the integration's automatic retry. The sentence for its card, or None."""
    from api.models.settings import AppSetting
    key = KEY.format(cfg_id)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    if ok or not retry:
        if row is not None:
            await db.delete(row)
        return None
    try:
        state = json.loads(row.value) if row and row.value else {}
    except ValueError:
        state = {}
    attempt = int(state.get("attempt") or 0) + 1
    if attempt > len(RETRY_MINUTES):
        if row is not None:
            await db.delete(row)
        return f"Retried automatically {len(RETRY_MINUTES)} times; the next scheduled sync tries again."
    at = datetime.now(timezone.utc) + timedelta(minutes=RETRY_MINUTES[attempt - 1])
    value = json.dumps({"attempt": attempt, "at": at.isoformat(), "dispatched_at": None})
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    return f"Retrying automatically at {at:%H:%M} UTC (attempt {attempt} of {len(RETRY_MINUTES)})."


async def dispatch_due(db) -> list[str]:
    """Hand the retries that are due to the workers (not while syncing is paused)."""
    from api.core import sync_pause
    from api.models.integration import IntegrationConfig
    from api.models.settings import AppSetting
    if await sync_pause.paused(db):
        return []
    now, sent = datetime.now(timezone.utc), []
    for row in (await db.execute(select(AppSetting).where(AppSetting.key.like("sync_retry.%")))).scalars().all():
        cfg_id = row.key.split(".", 1)[1]
        try:
            state = json.loads(row.value or "{}")
            at = datetime.fromisoformat(state["at"])
            given = datetime.fromisoformat(state["dispatched_at"]) if state.get("dispatched_at") else None
        except (ValueError, KeyError, TypeError):
            await db.delete(row)
            continue
        if at > now or (given and now - given < REDISPATCH_AFTER):
            continue
        cfg = await db.get(IntegrationConfig, cfg_id)
        if cfg is None or not cfg.is_enabled:
            await db.delete(row)
            continue
        from api.core.tasks import sync_integration
        sync_integration.delay(cfg_id)
        row.value = json.dumps({**state, "dispatched_at": now.isoformat()})
        sent.append(cfg_id)
        log.info("self-heal: retrying the sync of %s (attempt %s)", cfg_id, state.get("attempt"))
    await db.commit()
    return sent


def _redis():
    import redis

    from api.core.config import get_settings
    return redis.from_url(get_settings().redis_url, decode_responses=True, socket_timeout=5)


@task_success.connect
def _ran(sender=None, **_):
    """A daily job finished: its clock restarts."""
    name = getattr(sender, "name", None)
    if name in DAILY:
        try:
            _redis().set(RAN.format(name), str(time.time()))
        except Exception:  # noqa: BLE001 -- no Redis: the job still ran; at worst it runs once more
            log.warning("self-heal: couldn't record that %s ran", name)


def catch_up(r=None) -> list[str]:
    """Run each daily job that hasn't finished within its window (missed at its time of day)."""
    r = r or _redis()
    now, ran = time.time(), []
    for name, hours in DAILY.items():
        last = r.get(RAN.format(name))
        if last is None:   # first sight (or Redis was reset): start its clock instead of running everything now
            r.set(RAN.format(name), str(now))
            continue
        if now - float(last) > hours * 3600:
            r.set(RAN.format(name), str(now))   # claimed: not handed out again every 5 minutes while it runs
            celery_app.send_task(name)
            ran.append(name)
            log.warning("self-heal: %s hadn't run for %.0f hours; running it now", name, (now - float(last)) / 3600)
    return ran


@celery_app.task(name="api.core.self_heal.tick", ignore_result=True)
def tick():
    asyncio.run(_tick())


async def _tick():
    from api.core.db import get_session
    async for db in get_session():
        await dispatch_due(db)
        break
    try:
        catch_up()
    except Exception:  # noqa: BLE001 -- no Redis: retries above still ran
        log.warning("self-heal: daily-job check skipped (Redis?)")
