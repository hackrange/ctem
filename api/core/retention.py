"""Admin > Data retention: when a host counts as gone and its findings are removed (api/core/stale_hosts.py), and how
long a remediated finding is kept before it is rolled up and removed (api/core/finding_history.py).
Stored in app settings; STALE_HOST_DAYS seeds the default number of days."""
from __future__ import annotations

import json

from sqlalchemy import select

KEY = "data_retention"
LIMITS = {"stale_host_days": (7, 365), "probe_within_days": (1, 30), "remediated_days": (30, 365), "ip_history_days": (30, 3650)}


def defaults() -> dict:
    from api.core.config import get_settings
    return {"enabled": True, "stale_host_days": get_settings().stale_host_days, "probe_within_days": 7, "remediated_days": 90,
            "ip_history_days": 730}   # IP address usage history (api/core/ip_history.py): two years


def validate(raw: dict) -> dict:
    out = defaults()
    if not isinstance(raw, dict):
        raise ValueError("settings must be an object")
    if "enabled" in raw:
        if not isinstance(raw["enabled"], bool):
            raise ValueError("enabled is true or false")
        out["enabled"] = raw["enabled"]
    for k, (lo, hi) in LIMITS.items():
        if k in raw:
            v = raw[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f"{k} must be a whole number from {lo} to {hi}")
            out[k] = v
    return out


async def load(db) -> dict:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    try:
        return validate(json.loads(row.value)) if row and row.value else defaults()
    except ValueError:
        return defaults()


async def save(db, values: dict) -> dict:
    from api.models.settings import AppSetting
    good = validate(values)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=KEY, value=json.dumps(good)))
    else:
        row.value = json.dumps(good)
    await db.flush()
    return good
