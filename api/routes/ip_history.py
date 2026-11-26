"""Threat Hunt > IP Address Usage History (admin, cyber): who held an address, and when (GMT).

Search by an address (exactly, or anything in its /24, IPv6 /64), optionally at a moment or within a window, or by
an asset or a person to see every address they held. Each answer says how the address was tied to the asset and how
the person was tied to it. Times are GMT; the page shows them in another time zone on request. Every search is
audited. The address is encrypted at rest; it is found by its keyed hash, never by text."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.ip_history import IpSighting
from api.models.user import User

router = APIRouter(prefix="/api/v1/ip-history", tags=["hunt"])
SLACK = timedelta(hours=1)   # sightings are hourly: a moment within an hour of a span's ends counts as inside it


def _when(v: str | None, what: str) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, detail=f"{what} must be a date and time like 2026-03-12T14:00:00Z") from None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)   # no zone given: GMT


def _iso(d: datetime | None) -> str | None:
    if d is None:
        return None
    d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("")
async def search(ip: str | None = Query(None, max_length=45, pattern=r"^[0-9A-Fa-f:.]+$"),
                 scope: str = Query("exact", pattern="^(exact|net)$"),
                 at: str | None = Query(None, max_length=40), since: str | None = Query(None, alias="from", max_length=40),
                 until: str | None = Query(None, alias="to", max_length=40),
                 device: uuid.UUID | None = None, user: uuid.UUID | None = None,
                 limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000),
                 me: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    from api.core.encryption import search_hash
    from api.core.ip_history import net
    from api.models.settings import AuditLog
    where, what = [], []
    if ip:
        try:
            a = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise HTTPException(400, detail="That isn't an IP address") from None
        where.append(IpSighting.net_hash == search_hash(net(str(a))) if scope == "net" else IpSighting.ip_hash == search_hash(str(a)))
        what.append(f"{a}{'/net' if scope == 'net' else ''}")
    if device:
        where.append(IpSighting.device_id == str(device))
        what.append(f"device {device}")
    if user:
        where.append(IpSighting.user_id == str(user))
        what.append(f"person {user}")
    if not where:
        raise HTTPException(400, detail="Search by an IP address, an asset or a person")
    moment, start, end = _when(at, "at"), _when(since, "from"), _when(until, "to")
    if moment:
        where += [IpSighting.first_seen <= moment + SLACK, IpSighting.last_seen >= moment - SLACK]
        what.append(f"at {_iso(moment)}")
    if start:
        where.append(IpSighting.last_seen >= start)
    if end:
        where.append(IpSighting.first_seen <= end)
    total = (await db.execute(select(func.count()).select_from(IpSighting).where(*where))).scalar_one()
    rows = (await db.execute(select(IpSighting).where(*where).order_by(IpSighting.last_seen.desc(), IpSighting.id)
                             .limit(limit).offset(offset))).scalars().all()
    from api.models.device import Device
    devs = {d.id: d for d in (await db.execute(select(Device).where(Device.id.in_({r.device_id for r in rows if r.device_id})))).scalars()} if rows else {}
    people = {u.id: u for u in (await db.execute(select(User).where(User.id.in_({r.user_id for r in rows if r.user_id})))).scalars()} if rows else {}
    oldest = (await db.execute(select(func.min(IpSighting.first_seen)))).scalar_one_or_none()
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="hunt.ip_history", resource_type="ip_history",
                    detail=("searched " + ", ".join(what))[:300]))
    await db.commit()
    out = []
    for r in rows:
        d, p = devs.get(r.device_id), people.get(r.user_id)
        out.append({"ip": r.ip, "kind": r.kind, "first_seen": _iso(r.first_seen), "last_seen": _iso(r.last_seen), "sources": r.sources,
                    "asset": {"id": r.device_id, "hostname_then": r.hostname, "hostname_now": d.hostname if d else None,
                              "type": d.device_type.value if d is not None and d.device_type else None, "exists": d is not None},
                    "person": {"id": r.user_id, "name_then": r.username, "name_now": (p.display_name or p.username) if p else None,
                               "upn": p.upn if p else None},
                    "address_how": r.address_how, "person_how": r.person_how})
    return {"sightings": out, "total": total, "limit": limit, "offset": offset, "history_since": _iso(oldest)}
