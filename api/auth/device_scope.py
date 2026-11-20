"""SQL form of can_access_device, so list, count, and export queries agree with the detail check."""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import get_accessible_device_tag_ids
from api.models.device import Device, DeviceTag


async def device_scope(user, db: AsyncSession):
    """WHERE clause limiting Device rows to what the user may see, or None for global roles."""
    tag_ids = await get_accessible_device_tag_ids(user, db)
    if tag_ids is None:
        return None
    tagged = select(DeviceTag.device_id).where(DeviceTag.tag_id.in_(tag_ids or ["__none__"]))
    return or_(Device.id.in_(tagged), Device.owner_user_id == user.id)
