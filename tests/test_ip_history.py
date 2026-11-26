"""IP address usage history: hourly spans of asset + address + person (GMT), private and public, with how each link
was made; searched by address (exact or /24), moment, window, asset or person; admin and cyber only; kept as long as
Admin > Data retention says."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

T0 = datetime(2026, 3, 12, 14, 0, tzinfo=timezone.utc)


def test_kinds():
    from api.core.ip_history import kind, net
    assert kind("10.4.2.17") == "private" and kind("192.168.1.5") == "private" and kind("172.16.0.9") == "private"
    assert kind("8.8.8.8") == "public" and kind("2001:4860::8888") == "public"
    assert kind("127.0.0.1") is None and kind("169.254.1.1") is None and kind("nope") is None
    assert net("10.4.2.17") == "10.4.2.0/24"


async def _asset(db, tag, ip, public, owner=None):
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    d = Device(hostname=f"{tag}-pc", device_type=DeviceType.workstation, ip=ip, ip_hash=search_hash(ip), public_ip=public,
               public_ip_hash=search_hash(public), last_seen=T0, edr_last_seen=T0, owner_user_id=owner, sources=",crowdstrike,", edr_vendor="crowdstrike")
    db.add(d)
    await db.commit()
    return d


@pytest.mark.asyncio
async def test_spans_extend_split_and_explain(db):
    from api.core.ip_history import record
    from api.models.ip_history import IpSighting
    from api.models.user import User
    tag = f"ih{uuid.uuid4().hex[:6]}"
    u1 = User(username=f"{tag}a", display_name="Elmer Fudd", is_local=False, is_active=True)
    u2 = User(username=f"{tag}b", display_name="Daffy Duck", is_local=False, is_active=True)
    db.add_all([u1, u2])
    await db.commit()
    d = await _asset(db, tag, "10.250.7.33", "203.0.113.77", owner=u1.id)
    await record(db, T0)
    d.last_seen = d.edr_last_seen = T0 + timedelta(hours=1)
    await db.commit()
    await record(db, T0 + timedelta(hours=1))   # same asset, address, person: the span grows
    rows = (await db.execute(select(IpSighting).where(IpSighting.device_id == d.id))).scalars().all()
    assert len(rows) == 2 and {r.kind for r in rows} == {"private", "public"}
    priv = next(r for r in rows if r.kind == "private")
    gmt = lambda v: v if v.tzinfo else v.replace(tzinfo=timezone.utc)  # noqa: E731
    assert gmt(priv.first_seen) == T0 and gmt(priv.last_seen) == T0 + timedelta(hours=1) and priv.username == "Elmer Fudd"
    assert "CrowdStrike" in priv.address_how and "Detected user" in priv.person_how and "EDR" in priv.sources
    d.owner_user_id = u2.id
    d.last_seen = d.edr_last_seen = T0 + timedelta(hours=2)
    await db.commit()
    await record(db, T0 + timedelta(hours=2))   # a new person on it: a new span
    rows = (await db.execute(select(IpSighting).where(IpSighting.device_id == d.id, IpSighting.kind == "private"))).scalars().all()
    assert sorted(r.username for r in rows) == ["Daffy Duck", "Elmer Fudd"]
    await db.execute(delete(IpSighting).where(IpSighting.device_id == d.id))
    await db.commit()


@pytest.mark.asyncio
async def test_search_by_moment_range_asset_and_access(db, client_cyber, client_it_user):
    from api.core.ip_history import record
    from api.models.ip_history import IpSighting
    from api.models.settings import AuditLog
    tag = f"is{uuid.uuid4().hex[:6]}"
    d = await _asset(db, tag, "10.251.9.44", "198.51.100.88")
    await record(db, T0)
    url = "/api/v1/ip-history"
    assert (await client_it_user.get(url, params={"ip": "10.251.9.44"})).status_code == 403
    hit = (await client_cyber.get(url, params={"ip": "10.251.9.44", "at": "2026-03-12T14:30:00Z"})).json()
    assert hit["total"] == 1 and hit["sightings"][0]["asset"]["id"] == d.id and hit["sightings"][0]["first_seen"].endswith("Z")
    assert (await client_cyber.get(url, params={"ip": "10.251.9.44", "at": "2026-03-13T14:30:00Z"})).json()["total"] == 0
    assert (await client_cyber.get(url, params={"ip": "10.251.9.1", "scope": "net"})).json()["total"] >= 1   # its /24
    assert (await client_cyber.get(url, params={"device": d.id})).json()["total"] == 2                       # private and public
    assert (await client_cyber.get(url, params={"ip": "999.1.1.1"})).status_code == 400
    assert (await client_cyber.get(url, params={"ip": "10.0.0.1", "at": "yesterday"})).status_code == 400
    assert (await client_cyber.get(url)).status_code == 400
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "hunt.ip_history"))).scalars().first()
    await db.execute(delete(IpSighting).where(IpSighting.device_id == d.id))
    await db.commit()


@pytest.mark.asyncio
async def test_retention_setting_and_purge(db, client_admin, client_it_user):
    from api.core.ip_history import record
    from api.models.ip_history import IpSighting
    tag = f"ir{uuid.uuid4().hex[:6]}"
    d = await _asset(db, tag, "10.252.1.5", "198.51.100.99")
    await record(db, T0)
    cur = (await client_admin.get("/api/v1/retention")).json()
    assert cur["ip_history_days"] == 730 and "ip_history" in cur
    body = {k: cur[k] for k in ("enabled", "stale_host_days", "probe_within_days", "remediated_days")}
    assert (await client_admin.put("/api/v1/retention", json={**body, "ip_history_days": 10})).status_code == 422
    assert (await client_admin.put("/api/v1/retention", json={**body, "ip_history_days": 30})).status_code == 200
    d.last_seen = d.edr_last_seen = None
    await db.commit()
    await record(db, T0 + timedelta(days=45))   # 45 days on, with 30 kept: the March span goes
    assert not (await db.execute(select(IpSighting).where(IpSighting.device_id == d.id))).scalars().all()
    assert (await client_admin.put("/api/v1/retention", json={**body, "ip_history_days": 730})).status_code == 200
    assert (await client_it_user.get("/hunt/ip-history")).status_code == 404
