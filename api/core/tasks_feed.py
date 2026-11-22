"""Scheduled jobs for the alert feed (raise new alerts, send them to Splunk HEC) and hunting data retention, every
15 minutes."""
from __future__ import annotations

import asyncio

from api.core.tasks import celery_app

celery_app.conf.beat_schedule["alert-feed"] = {"task": "api.core.tasks_feed.alert_feed", "schedule": 900.0}


@celery_app.task(name="api.core.tasks_feed.alert_feed", ignore_result=True)
def alert_feed():
    asyncio.run(_alert_feed())


async def _alert_feed():
    from api.core import alert_delivery, alert_feed as feed
    from api.core.db import get_session
    async for db in get_session():
        await feed.raise_new(db)
        await alert_delivery.deliver(db)
        await feed.prune(db)
        from api.core.hunt_ingest import prune
        await prune(db)   # hunting data past its retention
        break
