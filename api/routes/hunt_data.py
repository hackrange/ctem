"""Threat hunting data (Threat Hunt > Telemetry): fleet stacks from endpoint telemetry, the hosts behind one, and
the EDR's real-time events. Admins and cyber only."""
from __future__ import annotations

from datetime import date, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/hunt/data", tags=["hunt"])
RARE = 3   # seen on this many hosts or fewer


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/stacks")
async def stacks(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                 q: str | None = Query(None, max_length=200), kind: Literal["process", "dns", "network", "logon", "logon_failed"] | None = None,
                 days: int = Query(7, ge=1, le=90), rare: bool = False, intel: bool = False,
                 sort: Literal["hosts", "events", "last_seen", "value"] = "hosts", order: Literal["asc", "desc"] = "desc",
                 limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100000)):
    """Stack counting: each distinct thing over the window, with how many hosts did it (rare ones on top when sorted
    ascending), how many days it was seen, and whether it matched threat intel."""
    from api.models.hunt_data import HuntStack
    since = date.today() - timedelta(days=days - 1)
    hosts, evs, last = func.max(HuntStack.host_count).label("hosts"), func.sum(HuntStack.events).label("events"), func.max(HuntStack.last_seen).label("last_seen")
    stmt = (select(HuntStack.key, HuntStack.kind, func.min(HuntStack.value).label("value"), func.min(HuntStack.sha256).label("sha256"),
                   hosts, evs, func.min(HuntStack.first_seen).label("first_seen"), last, func.count().label("days"),
                   func.max(case((HuntStack.intel_hit == True, 1), else_=0)).label("intel"))  # noqa: E712
            .where(HuntStack.day >= since).group_by(HuntStack.key, HuntStack.kind))
    if kind:
        stmt = stmt.where(HuntStack.kind == kind)
    if q and q.strip():
        like = _like(q.strip().lower())
        stmt = stmt.where(or_(func.lower(HuntStack.value).like(like, escape="\\"), HuntStack.sha256 == q.strip().lower()))
    if intel:
        stmt = stmt.where(HuntStack.intel_hit == True)  # noqa: E712
    if rare:
        stmt = stmt.having(func.max(HuntStack.host_count) <= RARE)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    col = {"hosts": hosts, "events": evs, "last_seen": last, "value": func.min(HuntStack.value)}[sort]
    rows = (await db.execute(stmt.order_by(col.asc() if order == "asc" else col.desc()).limit(limit).offset(offset))).all()
    return {"total": total, "days": days, "rare_at": RARE, "stacks": [
        {"key": r.key, "kind": r.kind, "value": r.value, "sha256": r.sha256, "hosts": r.hosts, "events": int(r.events or 0),
         "days": r.days, "first_seen": r.first_seen.isoformat() if r.first_seen else None,
         "last_seen": r.last_seen.isoformat() if r.last_seen else None, "intel": bool(r.intel)} for r in rows]}


@router.get("/stacks/{key}")
async def stack_hosts(key: str, _: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                      days: int = Query(7, ge=1, le=90)):
    """The hosts behind one stack (CTEM's assets where it knows them), a sample of its details, and any intel match."""
    import re

    from api.models.device import Device
    from api.models.hunt_data import HuntStack, IntelIndicator
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise HTTPException(404)
    since = date.today() - timedelta(days=days - 1)
    rows = (await db.execute(select(HuntStack).where(HuntStack.key == key, HuntStack.day >= since).order_by(HuntStack.day.desc()))).scalars().all()
    if not rows:
        raise HTTPException(404)
    aids = list(dict.fromkeys(a for r in rows for a in (r.hosts or [])))[:500]
    devs = {d.edr_device_id: d for d in (await db.execute(select(Device).where(Device.edr_device_id.in_(aids)))).scalars()} if aids else {}
    first = rows[0]
    probe = first.sha256 if first.kind == "process" else first.value.rsplit(":", 1)[0] if first.kind == "network" else first.value
    ind = (await db.execute(select(IntelIndicator).where(IntelIndicator.value == (probe or "").lower()))).scalars().first()
    return {"kind": first.kind, "value": first.value, "sha256": first.sha256, "fields": first.fields,
            "days": [{"day": r.day.isoformat(), "hosts": r.host_count, "events": r.events} for r in rows],
            "hosts": [{"edr_id": a, "asset_id": str(devs[a].id) if a in devs else None, "hostname": devs[a].hostname if a in devs else None}
                      for a in aids],
            "capped": any(r.host_count > len(r.hosts or []) for r in rows),
            "intel": {"value": ind.value, "type": ind.type, "confidence": ind.confidence, "actors": ind.actors, "malware": ind.malware,
                      "labels": ind.labels} if ind else None}


@router.get("/events")
async def edr_events(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                     q: str | None = Query(None, max_length=200), type: str | None = Query(None, max_length=64, pattern=r"^[A-Za-z0-9_]+$"),  # noqa: A002
                     limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100000)):
    from api.models.hunt_data import EdrEvent
    stmt = select(EdrEvent)
    if type:
        stmt = stmt.where(EdrEvent.type == type)
    if q and q.strip():
        like = _like(q.strip().lower())
        stmt = stmt.where(or_(func.lower(EdrEvent.hostname).like(like, escape="\\"), func.lower(EdrEvent.user).like(like, escape="\\"),
                              func.lower(EdrEvent.summary).like(like, escape="\\")))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(EdrEvent.at.desc()).limit(limit).offset(offset))).scalars().all()
    types = [t for (t,) in (await db.execute(select(EdrEvent.type).distinct().limit(100))).all()]
    return {"total": total, "types": sorted(types), "events": [
        {"type": e.type, "at": e.at.isoformat(), "hostname": e.hostname, "user": e.user, "severity": e.severity, "summary": e.summary,
         "event": e.event} for e in rows]}
