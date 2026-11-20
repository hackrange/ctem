"""How many machines each person has: assigned by someone, or seen signing in to."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

NO_DEVICES = {"devices_assigned": 0, "devices_detected": 0}


async def device_counts(db: AsyncSession, user_ids: list[str]) -> dict[str, dict]:
    """Per user: machines assigned to them, and machines they were seen on that nobody assigned."""
    from api.models.device import Device, DeviceAssignment

    if not user_ids:
        return {}
    out: dict[str, dict] = {}
    for uid, n in (await db.execute(select(DeviceAssignment.user_id, func.count()).where(
            DeviceAssignment.user_id.in_(user_ids)).group_by(DeviceAssignment.user_id))).all():
        out.setdefault(uid, dict(NO_DEVICES))["devices_assigned"] = n
    taken = select(DeviceAssignment.device_id).where(DeviceAssignment.user_id.is_not(None))
    for uid, n in (await db.execute(select(Device.owner_user_id, func.count()).where(
            Device.owner_user_id.in_(user_ids), Device.id.not_in(taken)).group_by(Device.owner_user_id))).all():
        out.setdefault(uid, dict(NO_DEVICES))["devices_detected"] = n
    return out
