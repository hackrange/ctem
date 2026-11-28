"""Scheduled PostgreSQL upkeep (api/core/db_maintenance.py): nightly at 02:15 UTC, with the index check on Sundays.
Also pins the other daily jobs to a time of day: threat intel at 01:30 UTC, the full rescore at 05:00 UTC."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from celery.schedules import crontab

from api.core.tasks import celery_app

celery_app.conf.beat_schedule["db-maintenance"] = {"task": "api.core.tasks_db.db_maintenance", "schedule": crontab(hour=2, minute=15)}
# The daily jobs at a time of day, not "every 24 hours from when the scheduler started": that timer restarts with
# every deploy, so with deploys more than once a day the full rescore never ran (scores went days without one)
celery_app.conf.beat_schedule["enrich-threat-intel"]["schedule"] = crontab(hour=1, minute=30)
celery_app.conf.beat_schedule["recalculate-all-risk-scores"]["schedule"] = crontab(hour=5, minute=0)


@celery_app.task(name="api.core.tasks_db.db_maintenance", ignore_result=True, time_limit=4 * 3600, soft_time_limit=4 * 3600 - 60)
def db_maintenance(reindex: bool | None = None):
    from api.core.db_maintenance import run
    weekly = datetime.now(timezone.utc).weekday() == 6 if reindex is None else reindex
    return asyncio.run(run(reindex=weekly))
