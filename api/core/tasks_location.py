"""Hourly: where each asset probably is (api/core/location.py). Daily: findings of hosts that are gone (api/core/stale_hosts.py)."""
from __future__ import annotations

import asyncio

from celery.schedules import crontab

from api.core.tasks import celery_app

celery_app.conf.beat_schedule["infer-locations"] = {"task": "api.core.tasks_location.infer_locations", "schedule": 3600.0}
# At a fixed time: a 24-hour timer would restart with every deploy and might never fire
celery_app.conf.beat_schedule["prune-stale-hosts"] = {"task": "api.core.tasks_location.prune_stale_hosts",
                                                      "schedule": crontab(hour=3, minute=30)}


@celery_app.task(name="api.core.tasks_location.infer_locations", ignore_result=True)
def infer_locations():
    asyncio.run(_infer())


async def _infer():
    from api.core import location
    from api.core.db import get_session
    async for db in get_session():
        await location.recompute(db)


@celery_app.task(name="api.core.tasks_location.prune_stale_hosts", ignore_result=True)
def prune_stale_hosts():
    """Daily: hosts no tool has seen in STALE_HOST_DAYS and the probe can't reach lose their findings (api/core/stale_hosts.py)."""
    asyncio.run(_prune())


async def _prune():
    from api.core import stale_hosts
    from api.core.db import get_session
    async for db in get_session():
        await stale_hosts.prune(db)
