"""Tags a feed owns on a device: added when the feed reports them, removed when it stops."""
from __future__ import annotations

import re

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

# Rapid7 tag types -> CTEM tag prefix. Criticality also lands on Device.criticality for scoring.
R7_PREFIX = {"custom": "r7", "location": "location", "owner": "owner", "criticality": "criticality"}
R7_MANAGED = tuple(f"{p}:" for p in R7_PREFIX.values())
CRITICALITY = {"very high": "Very High", "high": "High", "medium": "Medium", "low": "Low", "very low": "Very Low"}
_SPACE = re.compile(r"\s+")
_MAX_TAGS = 100


def clean(text) -> str | None:
    """One line, no control characters, short enough for a tag name."""
    if not isinstance(text, str):
        return None
    text = _SPACE.sub(" ", "".join(ch for ch in text if ord(ch) >= 32)).strip()
    return text[:110] or None


def r7_tags(raw) -> tuple[set[str], str | None]:
    """Rapid7 [{type, name}] -> (CTEM tag names, criticality level or None)."""
    names, crit = set(), None
    for t in (raw or [])[:_MAX_TAGS]:
        if not isinstance(t, dict):
            continue
        kind, name = str(t.get("type") or "custom").strip().lower(), clean(t.get("name"))
        if not name or kind not in R7_PREFIX:
            continue
        if kind == "criticality":
            crit = CRITICALITY.get(name.lower(), crit)
            if crit:
                names.add(f"criticality:{crit.lower()}")
            continue
        names.add(f"{R7_PREFIX[kind]}:{name.lower() if kind == 'custom' else name}")
    return names, crit


async def sync_tags(db: AsyncSession, device_id: str, wanted: set[str], managed: tuple[str, ...],
                    source: str, cache: dict) -> None:
    """Make the device's tags under `managed` prefixes exactly `wanted`; other tags are left alone."""
    from api.models.device import DeviceTag
    from api.models.tag import Tag

    rows = (await db.execute(select(Tag.name, Tag.id).join(DeviceTag, DeviceTag.tag_id == Tag.id)
                             .where(DeviceTag.device_id == device_id))).all()
    have = {name: tid for name, tid in rows}
    changed = False
    for name in wanted - have.keys():
        tid = cache.get(name)
        if tid is None:
            tid = (await db.execute(select(Tag.id).where(Tag.name == name))).scalar_one_or_none()
            if tid is None:
                tag = Tag(name=name, source=source)
                db.add(tag)
                await db.flush()
                tid = tag.id
            cache[name] = tid
        await db.execute(insert(DeviceTag).values(device_id=device_id, tag_id=tid))
        changed = True
    stale = [tid for name, tid in have.items() if name.startswith(managed) and name not in wanted]
    if stale:
        await db.execute(delete(DeviceTag).where(DeviceTag.device_id == device_id, DeviceTag.tag_id.in_(stale)))
        changed = True
    if changed:   # a repository's or site's tags feed its score (sensitive data it holds, environment)
        from api.scoring.dirty import mark_devices
        await mark_devices(db, [device_id])
