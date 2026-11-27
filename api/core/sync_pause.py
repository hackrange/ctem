"""Pause integration syncing (Settings > Integrations > Pause syncing): while paused no scheduled sync starts, Sync Now
and syncs already queued are skipped, and on-prem shipper uploads are refused with "send again on the next run" (the
shipper keeps its data and sends it then). Syncs already running finish, and scoring carries on, so the worker can
drain for maintenance. A pause can end on its own (30 minutes, 1 hour, 4 hours) or last until an admin resumes it.

Kept in the database (app_settings), so it holds across restarts and Redis loss; checking it is one indexed read."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.sync_pause")

KEY = "integrations.sync_paused"
DURATIONS = (30, 60, 240)   # minutes a pause may last; None = until resumed
MESSAGE = "Integration syncing is paused in CTEM; send again on the next run"


def _parse(raw: str | None) -> dict | None:
    try:
        v = json.loads(raw or "null")
    except ValueError:
        return None
    return v if isinstance(v, dict) and v.get("at") else None


async def state(db: AsyncSession) -> dict | None:
    """{by, at, until (None = until resumed)} while paused; None when syncing runs (a timed pause that has ended too)."""
    from api.models.settings import AppSetting
    raw = (await db.execute(select(AppSetting.value).where(AppSetting.key == KEY))).scalar_one_or_none()
    v = _parse(raw)
    if v is None:
        return None
    until = v.get("until")
    try:
        if until and datetime.fromisoformat(until) <= datetime.now(timezone.utc):
            return None
    except ValueError:
        return None
    return {"by": str(v.get("by") or "")[:128], "at": v["at"], "until": until}


async def paused(db: AsyncSession) -> bool:
    try:
        return await state(db) is not None
    except Exception:  # noqa: BLE001 -- a check that can't read the setting doesn't stop syncing
        log.warning("sync pause state unreadable; syncing as usual")
        return False


async def set_pause(db: AsyncSession, actor: str, minutes: int | None) -> dict:
    from api.models.settings import AppSetting
    now = datetime.now(timezone.utc)
    v = {"by": actor[:128], "at": now.isoformat(), "until": (now + timedelta(minutes=minutes)).isoformat() if minutes else None}
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=KEY, value=json.dumps(v)))
    else:
        row.value = json.dumps(v)
    return v


async def resume(db: AsyncSession) -> None:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    if row is not None:
        row.value = None
