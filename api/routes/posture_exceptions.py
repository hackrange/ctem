"""Posture exceptions (Cyber or Admin; every change audited): accept a failing EDR posture check on one device, every
device with a tag, every device of a type, or everywhere, with a reason and an end date (api/core/posture_exceptions.py)."""
from __future__ import annotations

import uuid
from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.core.posture_exceptions import label
from api.models.device import Device, DeviceType
from api.models.posture_exception import PostureException
from api.models.tag import Tag
from api.models.user import User
from api.routes.alert_allow import _until

router = APIRouter(prefix="/api/v1/posture-exceptions", tags=["devices"])
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]+$")]


class ExceptionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200, pattern=r"^[^\x00-\x1f<>]+$")]
    scope: Literal["device", "tag", "type", "all"]
    device_id: uuid.UUID | None = None
    tag_id: uuid.UUID | None = None
    device_type: DeviceType | None = None
    reason: Reason
    expires_on: date


class ExceptionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    expires_on: date | None = None
    reason: Reason | None = None


async def _tags(db: AsyncSession, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    return dict((await db.execute(select(Tag.id, Tag.name).where(Tag.id.in_(ids)))).all()) if ids else {}


def _view(e: PostureException, tags: dict[str, str]) -> dict:
    return {"id": str(e.id), "check": e.check, "scope": e.scope, "where": label(e, tags), "device_id": e.device_id,
            "tag_id": e.tag_id, "device_type": e.device_type, "reason": e.reason, "expires_at": e.expires_at.isoformat(),
            "enabled": e.enabled, "created_by": e.created_by, "created_at": e.created_at.isoformat() if e.created_at else None}


async def _audit(me: User, action: str, e: PostureException, detail: str, db: AsyncSession) -> None:
    from api.routes.admin import _audit as audit
    await audit(me, action, "posture_exception", str(e.id), detail[:500], db)


async def _get(db: AsyncSession, exc_id: uuid.UUID) -> PostureException:
    e = await db.get(PostureException, str(exc_id))
    if e is None:
        raise HTTPException(404)
    return e


@router.get("")
async def list_exceptions(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(PostureException).order_by(PostureException.created_at.desc()))).scalars().all()
    tags = await _tags(db, (e.tag_id for e in rows))
    return {"exceptions": [_view(e, tags) for e in rows]}


@router.post("", status_code=201)
async def add_exception(body: ExceptionBody, me: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """Exactly the target its scope needs: a device that exists, a tag that exists, or a device type."""
    e = PostureException(check=body.check, scope=body.scope, reason=body.reason, expires_at=_until(body.expires_on),
                         enabled=True, created_by=me.username)
    if body.scope == "device":
        if not body.device_id or await db.get(Device, str(body.device_id)) is None:
            raise HTTPException(422, detail="Pick the device.")
        e.device_id = str(body.device_id)
    elif body.scope == "tag":
        if not body.tag_id or await db.get(Tag, str(body.tag_id)) is None:
            raise HTTPException(422, detail="Pick the tag.")
        e.tag_id = str(body.tag_id)
    elif body.scope == "type":
        if not body.device_type:
            raise HTTPException(422, detail="Pick the device type.")
        e.device_type = body.device_type.value
    db.add(e)
    await db.flush()
    tags = await _tags(db, [e.tag_id])
    await _audit(me, "posture_exception.create", e, f"Excepted posture check '{e.check}' ({label(e, tags)}"
                 f"{f', device {e.device_id}' if e.device_id else ''}) until {body.expires_on}: {e.reason}", db)
    return _view(e, tags)


@router.put("/{exc_id}")
async def change_exception(exc_id: uuid.UUID, body: ExceptionPatch, me: User = Depends(require_cyber_or_admin),
                           db: AsyncSession = Depends(get_session)):
    e = await _get(db, exc_id)
    changed = []
    if body.enabled is not None and body.enabled != e.enabled:
        e.enabled = body.enabled
        changed.append("enabled" if body.enabled else "turned off")
    if body.expires_on is not None:
        e.expires_at = _until(body.expires_on)
        changed.append(f"until {body.expires_on}")
    if body.reason is not None:
        e.reason = body.reason
        changed.append("reason")
    await _audit(me, "posture_exception.update", e, f"Posture exception '{e.check}': {', '.join(changed) or 'no change'}", db)
    return _view(e, await _tags(db, [e.tag_id]))


@router.delete("/{exc_id}")
async def remove_exception(exc_id: uuid.UUID, me: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    e = await _get(db, exc_id)
    await _audit(me, "posture_exception.delete", e, f"Removed posture exception '{e.check}'", db)
    await db.delete(e)
    await db.commit()
    return {"ok": True}
