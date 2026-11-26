"""Recording IP address usage history (api/models/ip_history.py): once an hour, every asset a tool saw in the last few
hours, with its private and public address and the person on it, extends its current span or starts a new one.

A span stays open while the same asset keeps the same address with the same person; a gap longer than GAP, or a
change of person, starts a new span, so "who had this address at 14:00 GMT on 12 March" finds one answer. Loopback,
link-local and unspecified addresses are skipped. Spans older than the retention (Admin > Data retention, default two years) are deleted."""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.ip_history")
FRESH = timedelta(hours=3)        # an asset seen this recently is "on the network now"
GAP = timedelta(hours=6)          # longer without a sighting and the next one starts a new span
# Internal ranges: RFC 1918, carrier-grade NAT (RFC 6598) and IPv6 unique local (RFC 4193); anything else routable is public
PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))  # nosec -- classifying, not connecting
RETENTION_DAYS = 730   # the default; Admin > Data retention sets it (ip_history_days)


def _aw(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)   # stored without a zone means GMT


def kind(ip: str) -> str | None:
    """private (RFC 1918, carrier NAT, unique local IPv6 and similar internal ranges), public, or None to skip."""
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast:
        return None
    return "private" if any(a in n for n in PRIVATE if a.version == n.version) else "public"


def net(ip: str) -> str:
    a = ipaddress.ip_address(ip.strip())
    return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False))


FEED = {"crowdstrike": "CrowdStrike", "sentinelone": "SentinelOne", "defender": "Defender", "qualys": "Qualys", "rapid7": "Rapid7",
        "tenable": "Tenable", "ldap": "Active Directory", "okta": "Okta", "aws": "AWS", "azure": "Azure", "oci": "OCI", "horizon3": "NodeZero"}


def _address_how(d, ip: str, k: str, tools: list[str]) -> str:
    """How the address was tied to the asset: which field of its record, from which feeds, seen by which tools now."""
    feeds = [FEED.get(f, f.capitalize()) for f in (d.sources or d.source or "").strip(",").split(",") if f]
    role = "its public (internet-facing) address" if ip == (d.public_ip or "").strip() else "its own (local) address"
    seen = f"; reported in the last 3 hours by the {' and the '.join(t if t == 'EDR' else t.lower() for t in tools)}" if tools else ""
    return f"{k.capitalize()} address: {role} on the asset's record, from {', '.join(feeds[:5]) or 'a connected tool'}{seen}"[:300]


def _person(d, assignment, names: dict) -> tuple:
    """Who was on the asset, and how that was decided: the detected user (from sign-in data) first, as the one
    actually using it; else who CTEM says it's assigned to; else the last sign-in a tool reported."""
    if d.owner_user_id:
        return d.owner_user_id, names.get(d.owner_user_id), "Detected user: the person who signs in to this asset most (from sign-in data)"
    if assignment:
        uid, by = assignment
        return uid, names.get(uid), f"Assigned to them in CTEM{f' by {by}' if by else ''} (who should use it, not who signed in)"[:300]
    if d.last_login_user:
        via = FEED.get((d.edr_vendor or "").lower(), "a connected tool")
        return None, d.last_login_user, f"Last person to sign in, as reported by {via} (no matching directory person)"[:300]
    return None, None, "No person known for this asset at the time"


async def record(db: AsyncSession, now: datetime | None = None) -> int:
    """One pass; returns how many spans it opened or extended."""
    from api.core.encryption import search_hash
    from api.models.device import Device
    from api.models.ip_history import IpSighting
    from api.models.user import User
    now = now or datetime.now(timezone.utc)
    cut = now - FRESH
    devs = (await db.execute(select(Device).where(
        or_(Device.ip_hash.is_not(None), Device.public_ip_hash.is_not(None)),
        or_(Device.last_seen > cut, Device.edr_last_seen > cut)))).scalars().all()
    from api.core import retention
    keep = (await retention.load(db)).get("ip_history_days") or RETENTION_DAYS
    await db.execute(delete(IpSighting).where(IpSighting.last_seen < now - timedelta(days=keep))
                     .execution_options(synchronize_session=False))   # first: runs even when nothing is fresh
    if not devs:
        await db.commit()
        return 0
    from api.models.device import DeviceAssignment
    ids = [d.id for d in devs]
    assigned: dict = {}
    for chunk in [ids[i:i + 1000] for i in range(0, len(ids), 1000)]:
        assigned.update({did: (uid, by) for did, uid, by in (await db.execute(select(
            DeviceAssignment.device_id, DeviceAssignment.user_id, DeviceAssignment.assigned_by).where(
            DeviceAssignment.device_id.in_(chunk), DeviceAssignment.user_id.is_not(None)))).all()})
    owners = {d.owner_user_id for d in devs if d.owner_user_id} | {u for u, _ in assigned.values()}
    names = {}
    for chunk in [sorted(owners)[i:i + 1000] for i in range(0, len(owners), 1000)]:
        names.update({uid: (dn or un) for uid, dn, un in (await db.execute(
            select(User.id, User.display_name, User.username).where(User.id.in_(chunk)))).all()})
    open_rows: dict = {}
    for chunk in [ids[i:i + 1000] for i in range(0, len(ids), 1000)]:
        for r in (await db.execute(select(IpSighting).where(IpSighting.device_id.in_(chunk), IpSighting.last_seen > now - GAP))).scalars():
            key = (r.device_id, r.ip_hash, r.user_id)
            if key not in open_rows or _aw(r.last_seen) > _aw(open_rows[key].last_seen):
                open_rows[key] = r
    n = 0
    for d in devs:
        tools = [t for t, at in (("Scanner", _aw(d.last_seen)), ("EDR", _aw(d.edr_last_seen))) if at and at > cut]
        uid, person, person_how = _person(d, assigned.get(d.id), names)
        for ip in {x.strip() for x in (d.ip, d.public_ip) if x}:
            k = kind(ip)
            if k is None:
                continue
            h = search_hash(ip)
            row = open_rows.get((d.id, h, uid))
            if row is not None:
                row.last_seen = now
                row.sources = ", ".join(sorted(set(filter(None, (row.sources or "").split(", "))) | set(tools)))[:128]
                if d.hostname and row.hostname != d.hostname:
                    row.hostname = d.hostname[:255]
            else:
                db.add(IpSighting(ip=ip, ip_hash=h, net_hash=search_hash(net(ip)), kind=k, device_id=d.id, hostname=(d.hostname or "")[:255] or None,
                                  user_id=uid, username=person, sources=", ".join(tools)[:128] or None,
                                  address_how=_address_how(d, ip, k, tools), person_how=person_how, first_seen=now, last_seen=now))
            n += 1
    await db.commit()
    return n
