"""Accepted alerts (the allow list), for cyber and admin: list, accept, change and remove. Rules in api/core/alert_allow.py."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.alert_allow import AlertAllow
from api.models.user import User

router = APIRouter(prefix="/api/v1/threat/allow", tags=["threat"])
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300, pattern=r"^[^\x00-\x1f<>]+$")]
MAX_DAYS = 366


class AllowBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Text
    source: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{2,32}$")] | None = None
    hostname: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253, pattern=r"^[A-Za-z0-9._-]+$")] | None = None
    process: Annotated[str, StringConstraints(strip_whitespace=True, max_length=260, pattern=r"^[^\x00-\x1f<>]+$")] | None = None
    parent: Annotated[str, StringConstraints(strip_whitespace=True, max_length=260, pattern=r"^[^\x00-\x1f<>]+$")] | None = None
    file: Annotated[str, StringConstraints(strip_whitespace=True, max_length=400, pattern=r"^[^\x00-\x1f<>]+$")] | None = None
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")] | None = None
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]+$")]
    expires_on: date


class AllowPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    expires_on: date | None = None
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]+$")] | None = None


def _until(d: date) -> datetime:
    today = datetime.now(timezone.utc).date()
    if d <= today or d > today + timedelta(days=MAX_DAYS):
        raise HTTPException(422, detail=f"The end date must be after today and within {MAX_DAYS} days.")
    return datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=timezone.utc)


def describe(r: AlertAllow) -> str:
    return ", ".join(f"{k} {v}" for k, v in (("host", r.hostname), ("process", r.process), ("parent", r.parent),
                                              ("file", r.file), ("hash", r.sha256)) if v)


async def _audit(me: User, action: str, r: AlertAllow, detail: str, db: AsyncSession) -> None:
    from api.routes.admin import _audit as audit
    await audit(me, action, "alert_allow", str(r.id), detail[:500], db)


@router.get("")
async def list_allows(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    from api.core.alert_allow import view
    rows = (await db.execute(select(AlertAllow).order_by(AlertAllow.enabled.desc(), AlertAllow.expires_at.desc()))).scalars()
    return {"allows": [view(r) for r in rows]}


@router.get("/suggest")
async def suggest(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                  id: str = Query(..., min_length=14, max_length=300, pattern=r"^threat_alert_[^#\s]+(#\d{1,4})?$")):
    """What an entry for this alert would match on: its detection and source, and the host, process, file and hash
    its detail names, for the person to keep or clear."""
    from api.hunt.alert_detail import summarize
    from api.routes.threat import _alerts, _detail
    found = [a for a in await _alerts(db, id.partition("#")[0]) if a["id"] == id]
    if not found:
        raise HTTPException(404, detail="Alert not found")
    a = found[0]
    s = summarize(await _detail(db, id.partition("#")[0])) if a.get("has_detail") else {}
    return {"title": a.get("title"), "source": a.get("source"), "hostname": a.get("hostname"), "process": s.get("process"),
            "parent": s.get("parent"), "file": s.get("file"), "sha256": s.get("sha256")}


@router.post("", status_code=201)
async def add_allow(body: AllowBody, me: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    from api.core.alert_allow import view
    r = AlertAllow(title=body.title, source=body.source, hostname=body.hostname, process=body.process, parent=body.parent, file=body.file,
                   sha256=body.sha256.lower() if body.sha256 else None, reason=body.reason, expires_at=_until(body.expires_on),
                   enabled=True, created_by=me.username)
    db.add(r)
    await db.flush()
    scope = describe(r)
    await _audit(me, "alert_allow.create", r, f"Accepted alert '{r.title}'{f' ({scope})' if scope else ''} until "
                 f"{body.expires_on}: {r.reason}", db)
    return view(r)


@router.put("/{allow_id}")
async def change_allow(allow_id: uuid.UUID, body: AllowPatch, me: User = Depends(require_cyber_or_admin),
                       db: AsyncSession = Depends(get_session)):
    from api.core.alert_allow import view
    r = (await db.execute(select(AlertAllow).where(AlertAllow.id == str(allow_id)))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    changed = []
    if body.enabled is not None and body.enabled != r.enabled:
        r.enabled = body.enabled
        changed.append("enabled" if body.enabled else "turned off")
    if body.expires_on is not None:
        r.expires_at = _until(body.expires_on)
        changed.append(f"until {body.expires_on}")
    if body.reason is not None:
        r.reason = body.reason
        changed.append("reason")
    await _audit(me, "alert_allow.update", r, f"Accepted alert '{r.title}': {', '.join(changed) or 'no change'}", db)
    return view(r)


@router.delete("/{allow_id}")
async def remove_allow(allow_id: uuid.UUID, me: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    r = (await db.execute(select(AlertAllow).where(AlertAllow.id == str(allow_id)))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    await _audit(me, "alert_allow.delete", r, f"Removed accepted alert '{r.title}'", db)
    await db.delete(r)
    await db.commit()
    return {"ok": True}
