"""Who a device is assigned to and where it is (shipped, lost, stolen, returned), by admin and inventory;
Not In Scope, by admin and cyber."""
from __future__ import annotations

import logging
import uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.rbac import require_cyber_or_admin, require_permission
from api.core.db import get_session
from api.core.device_scope_exempt import MAX_DAYS
from api.core.device_scope_exempt import view as exempt_view
from api.models.device import DeviceAssignment
from api.models.settings import AuditLog
from api.models.user import User
from api.routes import device_query as dq
from api.routes.devices import _visible_device

log = logging.getLogger("open-ctem.device_assign")
# Literal paths ("/assignable-users") must register before the devices router's "/{device_id}"
router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=256, pattern=r"^[^\x00-\x1f]*$")]


class AssignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: uuid.UUID
    note: Note | None = None


class StatusBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["shipped", "lost", "stolen", "returned"] | None  # None = back in normal use
    note: Note | None = None
    carrier: Literal["ups", "fedex", "usps", "dhl"] | None = None
    tracking_number: Annotated[str, StringConstraints(strip_whitespace=True, to_upper=True,
                                                      pattern=r"^[A-Za-z0-9]{6,40}$")] | None = None

    @model_validator(mode="after")
    def _shipping(self):
        # A shipment needs both; anything else carries neither
        if self.status == "shipped" and not (self.carrier and self.tracking_number):
            raise ValueError("shipped needs a carrier and a tracking number")
        if self.status != "shipped" and (self.carrier or self.tracking_number):
            raise ValueError("carrier and tracking number only apply to shipped")
        return self


async def _row(device, db) -> DeviceAssignment:
    row = (await db.execute(select(DeviceAssignment).options(selectinload(DeviceAssignment.user))
                            .where(DeviceAssignment.device_id == device.id))).scalar_one_or_none()
    if row is None:
        row = DeviceAssignment(device_id=device.id)
        db.add(row)
    device.assignment = row  # keep the loaded device in step for anything that reads it next
    return row


def _audit(db, actor: User, action: str, device_id: str, detail: str | None) -> None:
    db.add(AuditLog(actor_user_id=str(actor.id), actor_username=actor.username, action=action,
                    resource_type="device", resource_id=device_id, detail=detail))


@router.get("/assignable-users")
async def assignable_users(
    current_user: User = Depends(require_permission("inventory", "write")),
    db: AsyncSession = Depends(get_session),
    q: str = Query(..., min_length=2, max_length=64),
):
    """Directory users for the Assign to picker: names only, 20 at most."""
    like = dq._like(q.strip())
    rows = (await db.execute(
        select(User).where(User.is_local.is_(False), User.username.ilike(like, escape="\\"))
        .order_by(func.lower(User.username)).limit(20))).scalars().all()
    return {"users": [{"id": str(u.id), "username": u.username, "name": u.display_name or u.username,
                       "title": u.title} for u in rows]}


@router.put("/{device_id}/assignment")
async def assign_device(
    device_id: uuid.UUID,
    body: AssignBody,
    current_user: User = Depends(require_permission("inventory", "write")),
    db: AsyncSession = Depends(get_session),
):
    device = await _visible_device(device_id, current_user, db)
    target = (await db.execute(select(User).where(User.id == str(body.user_id)))).scalar_one_or_none()
    if target is None or target.is_local:  # people from the directory, not break-glass app accounts
        raise HTTPException(400, detail="Unknown user")
    row = await _row(device, db)
    row.user, row.note, row.assigned_by = target, body.note, current_user.username[:128]
    _audit(db, current_user, "device.assign", str(device.id), f"assigned to {target.username}")
    await db.commit()
    return {"device_id": str(device.id), "user_id": str(target.id), "username": target.username}


@router.delete("/{device_id}/assignment", status_code=204)
async def unassign_device(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("inventory", "write")),
    db: AsyncSession = Depends(get_session),
):
    device = await _visible_device(device_id, current_user, db)
    row = (await db.execute(select(DeviceAssignment).where(DeviceAssignment.device_id == device.id))).scalar_one_or_none()
    if row is None or row.user_id is None:
        return
    row.user, row.note, row.assigned_by = None, None, current_user.username[:128]
    if row.status is None:  # nothing left worth keeping
        await db.delete(row)
        device.assignment = None
    _audit(db, current_user, "device.unassign", str(device.id), None)
    await db.commit()


@router.put("/{device_id}/status")
async def set_device_status(
    device_id: uuid.UUID,
    body: StatusBody,
    current_user: User = Depends(require_permission("inventory", "write")),
    db: AsyncSession = Depends(get_session),
):
    """Shipped, lost, stolen or returned; null puts it back in normal use."""
    device = await _visible_device(device_id, current_user, db)
    row = await _row(device, db)
    row.status, row.status_note = body.status, body.note if body.status else None
    row.carrier, row.tracking_number = body.carrier, body.tracking_number
    row.status_by, row.status_at = current_user.username[:128], datetime.now(timezone.utc)
    _audit(db, current_user, "device.status", str(device.id), body.status or "in use")
    await db.commit()
    return {"device_id": str(device.id), "status": row.status, "carrier": row.carrier,
            "tracking_number": row.tracking_number}


# ── Not In Scope ─────────────────────────────────────────────────────────────

class ScopeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    justification: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=1000,
                                                    pattern=r"^[^\x00-\x08\x0b-\x1f<>]+$")]
    expires_on: date

    @model_validator(mode="after")
    def _window(self):
        today = datetime.now(timezone.utc).date()
        if self.expires_on <= today:
            raise ValueError("expires_on must be a future date")
        if self.expires_on > today + timedelta(days=MAX_DAYS):
            raise ValueError(f"expires_on can be at most {MAX_DAYS} days away; renew it when it ends")
        return self


async def _rescore(device, db: AsyncSession) -> None:
    from api.scoring.engine import recalculate_device, refresh_affected_counts
    await recalculate_device(device, db)
    await db.commit()
    await refresh_affected_counts(db)


@router.put("/{device_id}/scope")
async def set_out_of_scope(
    device_id: uuid.UUID,
    body: ScopeBody,
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """Mark the device Not In Scope until the end of expires_on (UTC): its vulnerabilities stop counting."""
    device = await _visible_device(device_id, current_user, db)
    until = datetime.combine(body.expires_on + timedelta(days=1), time.min, tzinfo=timezone.utc)
    device.scope_exempt_until, device.scope_exempt_reason = until, body.justification
    device.scope_exempt_by, device.scope_exempt_at = current_user.username[:128], datetime.now(timezone.utc)
    _audit(db, current_user, "device.scope_out", str(device.id),
           f"Not In Scope through {body.expires_on.isoformat()}: {body.justification[:300]}")
    await db.commit()
    await _rescore(device, db)
    return {"device_id": str(device.id), "out_of_scope": exempt_view(device)}


@router.delete("/{device_id}/scope", status_code=204)
async def clear_out_of_scope(
    device_id: uuid.UUID,
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """Back in scope now: its vulnerabilities count again."""
    device = await _visible_device(device_id, current_user, db)
    if device.scope_exempt_until is None:
        return
    device.scope_exempt_until = device.scope_exempt_reason = device.scope_exempt_by = device.scope_exempt_at = None
    _audit(db, current_user, "device.scope_in", str(device.id), "back in scope")
    await db.commit()
    await _rescore(device, db)
