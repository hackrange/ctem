"""Daily, after the stale-host run: device counts, then remediated findings past the window rolled up and removed,
then old risk score history thinned (api/core/finding_history.py)."""
from __future__ import annotations

import asyncio
import logging

from celery.schedules import crontab

from api.core.tasks import celery_app

log = logging.getLogger("open-ctem.finding_history")
# At a fixed time, after prune-stale-hosts (03:30): a 24-hour timer would restart with every deploy
celery_app.conf.beat_schedule["finding-history"] = {"task": "api.core.tasks_history.finding_history",
                                                    "schedule": crontab(hour=4, minute=15)}


@celery_app.task(name="api.core.tasks_history.finding_history", ignore_result=True, time_limit=7200)
def finding_history():
    asyncio.run(_run())


async def _run():
    from api.core import finding_history as fh
    from api.core import retention
    from api.core.db import get_session
    from api.core.vuln_dashboard import forget_cached
    async for db in get_session():
        changed = await fh.snapshot_devices(db)
        await db.commit()
        removed = await fh.purge_remediated(db, (await retention.load(db))["remediated_days"])
        thinned = await fh.thin_score_history(db)
        await db.commit()
        log.info("finding history: %d device counts changed, %d remediated findings rolled up and removed, "
                 "%d old score entries thinned", changed, removed, thinned)
        if removed:
            await forget_cached()
