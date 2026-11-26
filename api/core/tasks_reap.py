"""Closes sync runs a stopped worker left "running" and frees their locks; a 6-hour backstop catches the rest."""
from __future__ import annotations

import asyncio
import logging
import socket
import uuid
from datetime import datetime, timedelta, timezone

from celery.signals import worker_ready
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.tasks import celery_app

log = logging.getLogger("open-ctem.tasks")

# Made once in the worker's main process, before it forks its pool, so every task of this worker start shares it
RUNNER = f"worker:{socket.gethostname()[:20]}:{uuid.uuid4().hex[:12]}"
STALE_AFTER = timedelta(hours=6)
INTERRUPTED = "Interrupted by a restart: the worker running it stopped. The next sync runs on schedule."
TOO_LONG = "Did not finish: no result after 6 hours. The next sync runs on schedule."
# Delete a lock only if it still holds the value we read (it can't be swapped between the read and the delete)
_DEL_IF = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0"

celery_app.conf.beat_schedule["reap-interrupted-syncs"] = {"task": "api.core.tasks.reap_interrupted_syncs",
                                                           "schedule": 900.0, "options": {"expires": 800}}


def _host(runner: str) -> str | None:
    parts = runner.split(":")
    return parts[1] if len(parts) == 3 and parts[0] == "worker" and parts[1] else None


def abandoned(runner: str | None, live_hosts: set[str], me: str = RUNNER) -> bool:
    """A worker start that is over: an earlier start on this host, or a host no worker answers from."""
    host = _host((runner or "").split("|")[0])
    if host is None or (runner or "").split("|")[0] == me:
        return False   # the app's, a collector's, one from before runner ids, or this worker's own
    return host == _host(me) or host not in live_hosts


def live_hosts() -> set[str] | None:
    """Hosts with a worker answering now; None when the ping fails (then only the 6-hour backstop applies)."""
    try:
        replies = celery_app.control.ping(timeout=2.0) or []
    except Exception:
        log.warning("worker ping failed; closing only runs older than 6 hours")
        return None
    return {name.split("@", 1)[-1][:20] for r in replies for name in r}


async def reap(db: AsyncSession, live: set[str] | None, me: str = RUNNER, now: datetime | None = None) -> int:
    """Close abandoned runs; returns how many."""
    from api.integrations.base import is_collector_fed
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus
    now = now or datetime.now(timezone.utc)
    running = SyncJob.status == SyncStatus.running
    gone: list[str] = []
    if live is not None:
        rows = (await db.execute(select(SyncJob.id, SyncJob.runner).where(running, SyncJob.runner.like("worker:%")))).all()
        gone = [j for j, r in rows if abandoned(r, live, me)]
    old = (await db.execute(select(SyncJob.id, SyncJob.integration_id).where(
        running, SyncJob.started_at < now - STALE_AFTER, SyncJob.id.not_in(gone or [""])))).all()
    collector = set()
    if old:
        cfgs = (await db.execute(select(IntegrationConfig).where(
            IntegrationConfig.id.in_({i for _, i in old})))).scalars().all()
        collector = {str(c.id) for c in cfgs if is_collector_fed(c)}
    too_long = [j for j, i in old if i not in collector]
    for ids, why in ((gone, INTERRUPTED), (too_long, TOO_LONG)):
        if ids:
            await db.execute(update(SyncJob).where(SyncJob.id.in_(ids), running)
                             .values(status=SyncStatus.failed, finished_at=now, error_message=why)
                             .execution_options(synchronize_session=False))
    await db.commit()
    return len(gone) + len(too_long)


async def free_locks(live: set[str], me: str = RUNNER) -> int:
    """Drop sync locks a stopped worker still holds, so its integrations sync again now rather than in 3 hours."""
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    freed = 0
    try:
        async for key in r.scan_iter("sync_lock:*"):
            value = await r.get(key)
            if value and "|" in value and abandoned(value, live, me):
                freed += int(await r.eval(_DEL_IF, 1, key, value) or 0)
    finally:
        await r.aclose()
    return freed


@celery_app.task(name="api.core.tasks.reap_interrupted_syncs", ignore_result=True, time_limit=300, soft_time_limit=240)
def reap_interrupted_syncs():
    asyncio.run(_reap(live_hosts()))


async def _reap(live: set[str] | None):
    from api.core.db import get_session
    async for db in get_session():
        n = await reap(db, live)
    locks = 0
    if live is not None:
        try:
            locks = await free_locks(live)
        except Exception:
            log.warning("could not check sync locks (Redis down?)")
    if n or locks:
        log.info("closed %d abandoned sync run(s), freed %d lock(s)", n, locks)


@worker_ready.connect
def _on_worker_ready(**kwargs):
    # Runs in the worker's main process: hand it to the pool, where the database is set up for tasks
    reap_interrupted_syncs.apply_async(countdown=5)
