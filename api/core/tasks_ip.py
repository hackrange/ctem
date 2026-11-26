"""The hourly IP address usage history task (api/core/ip_history.py), kept apart so api/core/tasks.py stays small."""
from __future__ import annotations

import asyncio
import logging

from api.core.tasks import celery_app

log = logging.getLogger("open-ctem.tasks")

# Which asset and person held each address, hour by hour
celery_app.conf.beat_schedule["record-ip-history"] = {"task": "api.core.tasks.record_ip_history", "schedule": 3600.0,
                                                      "options": {"expires": 3000}}


@celery_app.task(name="api.core.tasks.record_ip_history", ignore_result=True, time_limit=1200, soft_time_limit=1100)
def record_ip_history():
    asyncio.run(_record())


async def _record():
    from api.core.db import get_session
    from api.core.ip_history import record
    async for db in get_session():
        n = await record(db)
        log.info("IP history: %d spans opened or extended", n)
