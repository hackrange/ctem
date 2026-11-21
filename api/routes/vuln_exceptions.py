"""Vulnerability exceptions and finding proof.

Admin and cyber create exceptions (in effect at once) and approve or reject requests; IT users request them for
findings on devices they can see, and see their own requests and how they were decided. Every exception has a
reason and an end date at most a year out. Proof is fetched live from the scanner for one finding at a time.
"""
from __future__ import annotations

import logging
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import can_access_device, require_permission
from api.core import vuln_exceptions as vx
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import User
from api.models.vuln import ExceptionScope, ExceptionStatus, Finding, Vulnerability, VulnException

log = logging.getLogger("open-ctem.exceptions")
router = APIRouter(prefix="/api/v1/exceptions", tags=["exceptions"])
proof_router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

_DECIDERS = {"admin", "cyber"}
_REQUESTERS = _DECIDERS | {"it_user"}
Text = Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]*$")]
Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]*$")]
TABS = ("pending", "active", "mine", "rejected", "ended", "all")


def _decider(u: User) -> bool:
    return bool(_DECIDERS.intersection(u.role_names))


def _requester(u: User = Depends(get_current_user)) -> User:
    if not _REQUESTERS.intersection(u.role_names):
        raise HTTPException(404)
    return u


def _audit(db, u: User, action: str, exc_id: str, detail: str | None = None) -> None:
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action=action,
                    resource_type="vuln_exception", resource_id=exc_id, detail=(detail or "")[:500] or None))


class NewException(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vuln_id: uuid.UUID
    scope: Literal["finding", "devices", "all", "tag"]
    device_ids: list[uuid.UUID] = Field(default_factory=list, max_length=vx.MAX_DEVICES)
    tag_id: uuid.UUID | None = None
    reason: Text = Field(min_length=10)
    compensating_controls: Text | None = None
    expires_on: date

    @model_validator(mode="after")
    def _shape(self):
        today = datetime.now(timezone.utc).date()
        if self.expires_on <= today:
            raise ValueError("expires_on must be a future date")
        if self.expires_on > today + timedelta(days=vx.MAX_DAYS):
            raise ValueError(f"expires_on can be at most {vx.MAX_DAYS} days away")
        if self.scope in ("finding", "devices") and not self.device_ids:
            raise ValueError("pick at least one device")
        if self.scope == "finding" and len(self.device_ids) != 1:
            raise ValueError("a single-finding exception covers exactly one device")
        if self.scope == "tag" and not self.tag_id:
            raise ValueError("pick a tag")
        return self


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: Note | None = None
    expires_on: date | None = None   # an approver may shorten (or set) the end date


def _refuse(msg: str) -> dict:
    """A rule the person broke. 200 with ok=false, because the load balancer replaces 4xx bodies."""
    return {"ok": False, "error": msg}


async def _overlap(db, body: NewException, devices: list[str]) -> str | None:
    live = (await db.execute(select(VulnException).where(
        VulnException.vuln_id == str(body.vuln_id),
        VulnException.status.in_([ExceptionStatus.pending, ExceptionStatus.approved])))).scalars().all()
    for e in live:
        if e.status == ExceptionStatus.approved and not vx.is_active(e):
            continue
        if e.scope == ExceptionScope.all or body.scope == "all":
            return "This vulnerability already has an open or approved exception for all devices."
        if e.scope == ExceptionScope.tag and body.scope == "tag" and e.tag_id == str(body.tag_id):
            return "That tag already has an open or approved exception for this vulnerability."
        both = set(e.device_ids or []) & set(devices)
        if both:
            return f"{len(both)} of these devices already have an open or approved exception for this vulnerability."
    return None


@router.post("")
async def create(body: NewException, u: User = Depends(_requester), db: AsyncSession = Depends(get_session)):
    """Admin/cyber: in effect at once. IT users: a request for admin/cyber to decide."""
    from api.models.device import Device, DeviceTag
    from api.models.tag import Tag
    decide = _decider(u)
    vuln = await db.get(Vulnerability, str(body.vuln_id))
    if vuln is None:
        raise HTTPException(404)
    if not decide and body.scope in ("all", "tag"):
        return _refuse("IT users can request exceptions for chosen devices; ask cyber for all devices or a tag.")
    devices = list(dict.fromkeys(str(d) for d in body.device_ids))
    if devices:
        rows = (await db.execute(select(Device).options(selectinload(Device.tags).selectinload(DeviceTag.tag))
                                 .where(Device.id.in_(devices)))).scalars().all()
        found = {str(d.id) for d in rows}
        allowed = {str(d.id) for d in rows if decide or await can_access_device(u, d, db)}
        if len(allowed) != len(devices) or found != set(devices):
            raise HTTPException(404)   # same answer for "absent" and "not yours"
        with_finding = {r[0] for r in (await db.execute(select(Finding.device_id).where(
            Finding.vuln_id == vuln.id, Finding.device_id.in_(devices)))).all()}
        if with_finding != set(devices):
            return _refuse("Some of those devices don't have this vulnerability.")
    if body.scope == "tag" and await db.get(Tag, str(body.tag_id)) is None:
        raise HTTPException(404)
    clash = await _overlap(db, body, devices)
    if clash:
        return _refuse(clash)
    at = vx.now()
    exc = VulnException(vuln_id=vuln.id, scope=ExceptionScope(body.scope),
                        device_ids=devices if body.scope in ("finding", "devices") else None,
                        tag_id=str(body.tag_id) if body.scope == "tag" else None,
                        reason=body.reason, compensating_controls=body.compensating_controls or None,
                        expires_at=vx.end_of_day(body.expires_on),
                        status=ExceptionStatus.approved if decide else ExceptionStatus.pending,
                        requested_by_id=str(u.id), requested_by=u.username, requested_at=at,
                        decided_by=u.username if decide else None, decided_at=at if decide else None)
    db.add(exc)
    await db.flush()
    _audit(db, u, "exception.create" if decide else "exception.request", str(exc.id),
           f"{vuln.cve_id or vuln.title[:60]} {body.scope} until {body.expires_on.isoformat()}")
    touched = await vx.apply(db, exc) if decide else []
    await db.commit()
    await vx.rescore(db, touched)
    return {"ok": True, "id": str(exc.id), "status": exc.status.value, "findings_covered": exc.findings_covered}


async def _own_or_decider(db, u: User, exc_id: uuid.UUID) -> VulnException:
    exc = (await db.execute(select(VulnException).options(selectinload(VulnException.vuln))
                            .where(VulnException.id == str(exc_id)))).scalar_one_or_none()
    if exc is None or not (_decider(u) or exc.requested_by_id == str(u.id)):
        raise HTTPException(404)
    return exc


def _decider_only(u: User = Depends(_requester)) -> User:
    if not _decider(u):
        raise HTTPException(404)
    return u


@router.post("/{exc_id}/approve")
async def approve(exc_id: uuid.UUID, body: Decision, u: User = Depends(_decider_only),
                  db: AsyncSession = Depends(get_session)):
    exc = await _own_or_decider(db, u, exc_id)
    if exc.status != ExceptionStatus.pending:
        return _refuse("Only pending requests can be approved.")
    if body.expires_on:
        today = vx.now().date()
        if not today < body.expires_on <= today + timedelta(days=vx.MAX_DAYS):
            return _refuse(f"The end date must be in the next {vx.MAX_DAYS} days.")
        exc.expires_at = vx.end_of_day(body.expires_on)
    if vx._aware(exc.expires_at) <= vx.now():
        return _refuse("This request's end date has passed; set a new one to approve it.")
    exc.status, exc.decided_by, exc.decided_at = ExceptionStatus.approved, u.username, vx.now()
    exc.decision_note = body.note or None
    touched = await vx.apply(db, exc)
    _audit(db, u, "exception.approve", str(exc.id), body.note)
    await db.commit()
    await vx.rescore(db, touched)
    return {"ok": True, "status": exc.status.value, "findings_covered": exc.findings_covered}


async def _close(db, u: User, exc_id: uuid.UUID, body: Decision, want: ExceptionStatus, to: ExceptionStatus,
                 action: str, needs_note: bool, owner_only: bool = False) -> dict:
    exc = await _own_or_decider(db, u, exc_id)
    if owner_only and exc.requested_by_id != str(u.id):
        raise HTTPException(404)
    if exc.status != want:
        return _refuse(f"Only {want.value} exceptions can be {to.value}.")
    if needs_note and not (body.note and len(body.note) >= 3):
        return _refuse("Add a short note saying why.")
    touched = await vx.release(db, exc) if want == ExceptionStatus.approved else []
    exc.status, exc.decided_by, exc.decided_at = to, u.username, vx.now()
    exc.decision_note = body.note or exc.decision_note
    _audit(db, u, action, str(exc.id), body.note)
    await db.commit()
    await vx.rescore(db, touched)
    return {"ok": True, "status": exc.status.value}


@router.post("/{exc_id}/reject")
async def reject(exc_id: uuid.UUID, body: Decision, u: User = Depends(_decider_only), db: AsyncSession = Depends(get_session)):
    return await _close(db, u, exc_id, body, ExceptionStatus.pending, ExceptionStatus.rejected, "exception.reject", True)


@router.post("/{exc_id}/revoke")
async def revoke(exc_id: uuid.UUID, body: Decision, u: User = Depends(_decider_only), db: AsyncSession = Depends(get_session)):
    return await _close(db, u, exc_id, body, ExceptionStatus.approved, ExceptionStatus.revoked, "exception.revoke", True)


@router.post("/{exc_id}/cancel")
async def cancel(exc_id: uuid.UUID, body: Decision, u: User = Depends(_requester), db: AsyncSession = Depends(get_session)):
    return await _close(db, u, exc_id, body, ExceptionStatus.pending, ExceptionStatus.cancelled, "exception.cancel",
                        False, owner_only=True)


def _tab_filter(tab: str, u: User):
    now = vx.now()
    S = ExceptionStatus
    if tab == "pending":
        return VulnException.status == S.pending
    if tab == "active":
        return (VulnException.status == S.approved) & (VulnException.expires_at > now)
    if tab == "rejected":
        return VulnException.status == S.rejected
    if tab == "ended":
        return VulnException.status.in_([S.expired, S.revoked, S.cancelled])
    if tab == "mine":
        return VulnException.requested_by_id == str(u.id)
    return None


async def _names(db, excs: list[VulnException]) -> tuple[dict, dict]:
    from api.models.device import Device
    from api.models.tag import Tag
    from api.routes import device_query as dq
    ids = {d for e in excs for d in (e.device_ids or [])[:5]}
    hosts = {str(d.id): dq.short_name(d.hostname) for d in (await db.execute(select(Device).where(Device.id.in_(ids)))).scalars()} if ids else {}
    tids = {e.tag_id for e in excs if e.tag_id}
    tags = {str(t.id): t.name for t in (await db.execute(select(Tag).where(Tag.id.in_(tids)))).scalars()} if tids else {}
    return hosts, tags


def _row(e: VulnException, hosts: dict, tags: dict, full: bool = False) -> dict:
    v = e.vuln
    devs = e.device_ids or []
    covers = {"finding": hosts.get(devs[0], "1 device") if devs else "1 device",
              "devices": f"{len(devs)} devices" + (f": {', '.join(hosts[d] for d in devs[:3] if d in hosts)}" if devs else ""),
              "all": "All devices", "tag": f"Tag: {tags[e.tag_id].upper() if e.tag_id in tags else 'removed tag'}"}[e.scope.value]
    out = {"id": str(e.id), "vuln_id": str(e.vuln_id), "cve_id": v.cve_id if v else None,
           "title": v.title if v else None, "scope": e.scope.value, "covers": covers,
           "status": "expired" if e.status == ExceptionStatus.approved and not vx.is_active(e) else e.status.value,
           "expires_at": vx._aware(e.expires_at).isoformat(), "requested_by": e.requested_by,
           "requested_at": vx._aware(e.requested_at).isoformat(), "decided_by": e.decided_by,
           "decided_at": vx._aware(e.decided_at).isoformat() if e.decided_at else None,
           "findings_covered": e.findings_covered, "reason": e.reason}
    if full:
        out.update({"compensating_controls": e.compensating_controls, "decision_note": e.decision_note,
                    "device_ids": devs, "devices": [{"id": d, "hostname": hosts.get(d)} for d in devs]})
    return out


@router.get("")
async def list_exceptions(u: User = Depends(_requester), db: AsyncSession = Depends(get_session),
                          tab: str = Query("all", pattern="^(" + "|".join(TABS) + ")$"),
                          q: str | None = Query(None, max_length=200),
                          limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100_000)):
    stmt = select(VulnException).join(Vulnerability, Vulnerability.id == VulnException.vuln_id)
    if not _decider(u):   # IT users only ever see their own
        stmt = stmt.where(VulnException.requested_by_id == str(u.id))
    cond = _tab_filter(tab, u)
    if cond is not None:
        stmt = stmt.where(cond)
    if q and q.strip():
        like = "%" + q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(or_(func.lower(Vulnerability.title).like(like, escape="\\"),
                              func.lower(func.coalesce(Vulnerability.cve_id, "")).like(like, escape="\\"),
                              func.lower(VulnException.requested_by).like(like, escape="\\")))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.options(selectinload(VulnException.vuln))
                             .order_by(VulnException.requested_at.desc()).limit(limit).offset(offset))).scalars().all()
    hosts, tags = await _names(db, rows)
    return {"exceptions": [_row(e, hosts, tags) for e in rows], "total": total, "limit": limit, "offset": offset,
            "can_decide": _decider(u)}


@router.get("/summary")
async def summary(u: User = Depends(_requester), db: AsyncSession = Depends(get_session)):
    """Counts for the menu badge: requests waiting (admin/cyber), or your own decided in the last week."""
    if _decider(u):
        n = (await db.execute(select(func.count()).select_from(VulnException)
                              .where(VulnException.status == ExceptionStatus.pending))).scalar_one()
        return {"pending": n, "can_decide": True}
    since = vx.now() - timedelta(days=7)
    mine = (await db.execute(select(VulnException.status, func.count()).where(
        VulnException.requested_by_id == str(u.id),
        or_(VulnException.status == ExceptionStatus.pending, VulnException.decided_at >= since))
        .group_by(VulnException.status))).all()
    return {"mine": {s.value: n for s, n in mine}, "can_decide": False}


@router.get("/{exc_id}")
async def get_exception(exc_id: uuid.UUID, u: User = Depends(_requester), db: AsyncSession = Depends(get_session)):
    exc = await _own_or_decider(db, u, exc_id)
    from api.models.device import Device
    from api.routes import device_query as dq
    devs = exc.device_ids or []
    hosts = {str(d.id): dq.short_name(d.hostname) for d in (await db.execute(
        select(Device).where(Device.id.in_(devs[:vx.MAX_DEVICES])))).scalars()} if devs else {}
    _, tags = await _names(db, [exc])
    return {**_row(exc, hosts, tags, full=True), "can_decide": _decider(u),
            "can_cancel": exc.requested_by_id == str(u.id) and exc.status == ExceptionStatus.pending}


@proof_router.get("/{finding_id}/proof")
async def finding_proof(finding_id: uuid.UUID, u: User = Depends(require_permission("findings", "read")),
                        db: AsyncSession = Depends(get_session)):
    """The scanner's evidence for one finding (where and what it found), fetched live."""
    from api.core.finding_proof import fetch
    from api.models.device import Device, DeviceTag
    f = (await db.execute(select(Finding).options(selectinload(Finding.device).selectinload(Device.tags)
                                                  .selectinload(DeviceTag.tag), selectinload(Finding.vuln))
                          .where(Finding.id == str(finding_id)))).scalar_one_or_none()
    if f is None or not await can_access_device(u, f.device, db):
        raise HTTPException(404)
    out = await fetch(db, f)
    exc = await db.get(VulnException, f.exception_id) if f.exception_id else None
    return {**out, "hostname": f.device.hostname if f.device else None, "cve_id": f.vuln.cve_id if f.vuln else None,
            "title": f.vuln.title if f.vuln else None, "source": f.source,
            "exception": {"id": str(exc.id), "expires_at": vx._aware(exc.expires_at).isoformat()} if exc else None}
