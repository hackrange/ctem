"""Which posture exceptions apply to a device, and marking its checks with them (api/models/posture_exception.py)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.posture_exception import PostureException


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


async def for_device(db: AsyncSession, device) -> list[PostureException]:
    """Exceptions in force for this device: its own, its tags', its type's and the ones for everywhere."""
    tags = [str(t.tag_id) for t in (getattr(device, "tags", None) or [])]
    dtype = device.device_type.value if getattr(device, "device_type", None) is not None else None
    who = [PostureException.scope == "all", PostureException.device_id == str(device.id)]
    if tags:
        who.append(PostureException.tag_id.in_(tags))
    if dtype:
        who.append((PostureException.scope == "type") & (PostureException.device_type == dtype))
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(PostureException).where(PostureException.enabled == True, or_(*who)))).scalars().all()  # noqa: E712
    return [e for e in rows if _aware(e.expires_at) > now]


def label(e: PostureException, tags: dict[str, str] | None = None) -> str:
    if e.scope == "device":
        return "This device"
    if e.scope == "tag":
        return f"Tag: {(tags or {}).get(e.tag_id, 'a tag')}"
    if e.scope == "type":
        return f"All {(e.device_type or '').replace('_', ' ')}s"
    return "Everywhere"


def apply(view: dict, excs: list[PostureException], tags: dict[str, str] | None = None) -> dict:
    """Mark each check an exception covers (the narrowest wins); failing counts leave excepted checks out."""
    order = {"device": 0, "tag": 1, "type": 2, "all": 3}
    by_check: dict[str, PostureException] = {}
    for e in sorted(excs, key=lambda e: order.get(e.scope, 9)):
        by_check.setdefault(e.check.strip().lower(), e)
    for s in view.get("signals") or []:
        e = by_check.get(str(s.get("name") or "").strip().lower())
        if e:
            s["excepted"] = {"id": str(e.id), "scope": label(e, tags), "reason": e.reason, "by": e.created_by,
                             "until": _aware(e.expires_at).date().isoformat()}
    view["failing"] = sum(1 for s in view.get("signals") or [] if s.get("passed") is False and not s.get("excepted"))
    return view
