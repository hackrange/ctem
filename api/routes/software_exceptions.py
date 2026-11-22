"""Software exceptions, one asset at a time: allow a title on an asset although it's unauthorized elsewhere, or
not allow it on an asset although it's approved. A reason is required; an end date is optional (at most 2 years).
Admins and cyber only; audited."""
from __future__ import annotations

import uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.device import Device
from api.models.settings import AuditLog
from api.models.software import SoftwareException, SoftwareTitle
from api.models.user import User

router = APIRouter(prefix="/api/v1/software", tags=["software"])


class ExceptionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["allowed", "denied"]
    reason: str = Field(min_length=5, max_length=1000, pattern=r"^[^<>\x00-\x08\x0b-\x1f]*$")
    expires_on: date | None = None

    @field_validator("expires_on")
    @classmethod
    def _within(cls, v):
        today = datetime.now(timezone.utc).date()
        if v is not None and not today <= v <= today + timedelta(days=730):
            raise ValueError("the end date must be from today to 2 years ahead")
        return v


async def _pair(db, u: User, title_id: uuid.UUID, device_id: uuid.UUID) -> tuple[SoftwareTitle, Device]:
    if not {"admin", "cyber"} & set(u.role_names):
        raise HTTPException(404)
    t, d = await db.get(SoftwareTitle, str(title_id)), await db.get(Device, str(device_id))
    if t is None or d is None:
        raise HTTPException(404)
    return t, d


@router.put("/{title_id}/exceptions/{device_id}")
async def set_exception(u: User = Depends(require_permission("devices", "read")), *, title_id: uuid.UUID,
                        device_id: uuid.UUID, body: ExceptionBody, db: AsyncSession = Depends(get_session)):
    t, d = await _pair(db, u, title_id, device_id)
    e = (await db.execute(select(SoftwareException).where(SoftwareException.title_id == t.id,
                                                          SoftwareException.device_id == d.id))).scalar_one_or_none()
    if e is None:
        e = SoftwareException(title_id=t.id, device_id=d.id, decision=body.decision, reason=body.reason.strip(),
                              decided_by=u.username)
        db.add(e)
    e.decision, e.reason, e.decided_by = body.decision, body.reason.strip(), u.username
    e.expires_at = datetime.combine(body.expires_on, time(23, 59, 59), tzinfo=timezone.utc) if body.expires_on else None
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="software.exception",
                    resource_type="software", resource_id=str(t.id),
                    detail=f"{t.title} on {d.hostname}: {body.decision}{' until ' + body.expires_on.isoformat() if body.expires_on else ''}"[:300]))
    await db.commit()
    return {"ok": True, "exception": {"decision": e.decision, "reason": e.reason, "decided_by": e.decided_by,
                                      "expires_at": e.expires_at.isoformat() if e.expires_at else None}}


@router.delete("/{title_id}/exceptions/{device_id}")
async def remove_exception(title_id: uuid.UUID, device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                           db: AsyncSession = Depends(get_session)):
    t, d = await _pair(db, u, title_id, device_id)
    e = (await db.execute(select(SoftwareException).where(SoftwareException.title_id == t.id,
                                                          SoftwareException.device_id == d.id))).scalar_one_or_none()
    if e is None:
        raise HTTPException(404)
    await db.delete(e)
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="software.exception_removed",
                    resource_type="software", resource_id=str(t.id), detail=f"{t.title} on {d.hostname}"[:300]))
    await db.commit()
    return {"ok": True}
