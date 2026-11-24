"""SQL form of can_access_device, so list, count, and export queries agree with the detail check."""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import get_accessible_device_tag_ids
from api.models.device import Device, DeviceAssignment, DeviceTag


async def device_scope(user, db: AsyncSession):
    """WHERE clause limiting Device rows to what the user may see, or None for global roles."""
    tag_ids = await get_accessible_device_tag_ids(user, db)
    if tag_ids is None:
        return None
    tagged = select(DeviceTag.device_id).where(DeviceTag.tag_id.in_(tag_ids or ["__none__"]))
    # Assignment is set by a person; the sign-in-detected owner never grants access
    assigned = select(DeviceAssignment.device_id).where(DeviceAssignment.user_id == user.id)
    return or_(Device.id.in_(tagged), Device.id.in_(assigned))


async def access_key(user, db: AsyncSession) -> str:
    """A short fingerprint of what this person may see (their tags and assigned devices), so a cached view of their
    data is never served after that changes. "all" for fleet-wide roles."""
    import hashlib
    import json
    tag_ids = await get_accessible_device_tag_ids(user, db)
    if tag_ids is None:
        return "all"
    assigned = sorted(str(x) for x in (await db.execute(
        select(DeviceAssignment.device_id).where(DeviceAssignment.user_id == user.id))).scalars())
    return hashlib.sha256(json.dumps([sorted(map(str, tag_ids)), assigned]).encode()).hexdigest()[:16]
