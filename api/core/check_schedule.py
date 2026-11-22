"""How often the CTEM control checks run (GRC > CTEM Control Checks > Run schedule, admins).

One interval for every check, and optional per-check intervals. The scheduler looks every 15 minutes and runs each
check whose newest result is older than its interval (or that has none), so 1 hour is the shortest useful value."""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

KEY = "grc_check_schedule"
CHOICES = (1, 2, 4, 6, 8, 12, 24)   # hours
DEFAULTS = {"default_hours": 24, "checks": {}}


def clean(raw) -> dict:
    out = {"default_hours": DEFAULTS["default_hours"], "checks": {}}
    if isinstance(raw, dict):
        if raw.get("default_hours") in CHOICES:
            out["default_hours"] = raw["default_hours"]
        out["checks"] = {str(k)[:64]: v for k, v in (raw.get("checks") or {}).items() if v in CHOICES}
    return out


async def load(db: AsyncSession) -> dict:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    try:
        return clean(json.loads(row.value)) if row and row.value else clean(None)
    except ValueError:
        return clean(None)


async def save(db: AsyncSession, raw: dict) -> dict:
    from api.models.settings import AppSetting
    good = clean(raw)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=KEY, value=json.dumps(good)))
    else:
        row.value = json.dumps(good)
    await db.flush()
    return good


def hours_for(rules: dict, check_type: str) -> int:
    return rules["checks"].get(check_type, rules["default_hours"])
