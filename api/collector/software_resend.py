"""Ask a shipper's console source for software sooner, once: "Software every" is shortened, and put back as soon
as a run delivers software (api/collector/ingest.py). Used after the name rules change to resend cleanly."""
from __future__ import annotations

import copy

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

KEY = "software.restore_hours.{}"
KIND = "rapid7_console"


async def resend_soon(db: AsyncSession, prof, hours: int = 4) -> int:
    """Shorten this profile's console software interval; returns the interval it goes back to."""
    from api.collector import service
    from api.models.settings import AppSetting
    mods = copy.deepcopy(prof.modules or {})
    src = mods.get(KIND)
    if not src:
        raise ValueError("this shipper has no console source")
    settings = src.setdefault("settings", {})
    key = KEY.format(prof.id)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    back = int(row.value) if row else int(settings.get("software_hours", 24) or 24)
    if row is None:
        db.add(AppSetting(key=key, value=str(back)))
    settings["software_hours"] = hours
    await service.save_profile_modules(db, prof, mods)
    return back


async def restore(db: AsyncSession, integration_id: str) -> bool:
    """After a run of this console integration delivered software: put the interval back, if it was shortened."""
    from api.collector import service
    from api.models.collector import CollectorProfile
    from api.models.settings import AppSetting
    for prof in (await db.execute(select(CollectorProfile))).scalars():
        src = (prof.modules or {}).get(KIND) or {}
        if str(src.get("integration_id")) != str(integration_id):
            continue
        row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY.format(prof.id)))).scalar_one_or_none()
        if row is None:
            return False
        mods = copy.deepcopy(prof.modules)
        mods[KIND].setdefault("settings", {})["software_hours"] = int(row.value)
        await service.save_profile_modules(db, prof, mods)
        await db.delete(row)
        return True
    return False
