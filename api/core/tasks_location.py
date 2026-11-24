"""Hourly: where each asset probably is (api/core/location.py), from the EDR's sites, people's offices and neighbors."""
from __future__ import annotations

import asyncio

from api.core.tasks import celery_app

celery_app.conf.beat_schedule["infer-locations"] = {"task": "api.core.tasks_location.infer_locations", "schedule": 3600.0}


@celery_app.task(name="api.core.tasks_location.infer_locations", ignore_result=True)
def infer_locations():
    asyncio.run(_infer())


async def _infer():
    from api.core import location
    from api.core.db import get_session
    async for db in get_session():
        await location.recompute(db)
