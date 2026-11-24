"""What each person has hidden for themselves: dashboard Serious findings and Threat page alerts. Kept on their
account (one app setting per user), so it follows them across browsers and never changes what anyone else sees."""
from __future__ import annotations

import json
import re

from sqlalchemy import select

KINDS = {"watch": re.compile(r"^[0-9a-f]{16}$"), "alert": re.compile(r"^threat_alert_[^#\s]{1,280}(#\d{1,4})?$")}
MAX_PER_KIND = 5000


def _key(user_id: str) -> str:
    return f"hidden.{user_id}"


async def load(db, user_id: str) -> dict[str, set]:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == _key(user_id)))).scalar_one_or_none()
    try:
        raw = json.loads(row.value) if row and row.value else {}
    except ValueError:
        raw = {}
    return {k: {x for x in raw.get(k, []) if isinstance(x, str) and KINDS[k].match(x)} for k in KINDS}


async def set_hidden(db, user_id: str, kind: str, item: str, hidden: bool) -> dict[str, set]:
    from api.models.settings import AppSetting
    if kind not in KINDS or not KINDS[kind].match(item or ""):
        raise ValueError("unknown item")
    have = await load(db, user_id)
    (have[kind].add if hidden else have[kind].discard)(item)
    if len(have[kind]) > MAX_PER_KIND:
        raise ValueError(f"at most {MAX_PER_KIND} hidden {kind} items; unhide some first")
    row = (await db.execute(select(AppSetting).where(AppSetting.key == _key(user_id)))).scalar_one_or_none()
    value = json.dumps({k: sorted(v) for k, v in have.items()})
    if row is None:
        db.add(AppSetting(key=_key(user_id), value=value, is_sensitive=False))
    else:
        row.value = value
    await db.commit()
    return have
