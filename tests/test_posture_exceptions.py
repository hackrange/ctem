"""Posture exceptions: a failing EDR posture check accepted on one device, a tag's devices, a device type or everywhere
(Cyber or Admin, a reason and an end date, audited), shown as Excepted and left out of the failing count."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

CHECK = "LT Terminal Fault Mitigation"


def _posture():
    return {"overall": 60, "at": "2026-11-20T00:00:00Z", "signals": [
        {"name": CHECK, "meets": "no", "kind": "os", "criteria": "L1TF mitigations on"},
        {"name": "Firewall on", "meets": "yes", "kind": "os"},
        {"name": "Sensor tamper protection", "meets": "no", "kind": "sensor"}]}


async def _devices(db, tag):
    from api.models.device import Device, DeviceTag, DeviceType
    from api.models.tag import Tag
    t = Tag(name=f"app-{tag}", source="manual")
    a = Device(hostname=f"ws-a-{tag}", device_type=DeviceType.workstation, edr_posture=_posture())
    b = Device(hostname=f"ws-b-{tag}", device_type=DeviceType.workstation, edr_posture=_posture())
    s = Device(hostname=f"srv-{tag}", device_type=DeviceType.server, edr_posture=_posture())
    db.add_all([t, a, b, s])
    await db.flush()
    db.add(DeviceTag(device_id=str(a.id), tag_id=str(t.id)))
    await db.commit()
    return t, a, b, s


async def _state(client, d):
    p = (await client.get(f"/api/v1/devices/{d.id}/posture")).json()
    sig = {x["name"]: x for x in p["signals"]}
    return bool(sig[CHECK].get("excepted")), p["failing"], p


@pytest.mark.asyncio
async def test_each_scope_reaches_exactly_its_devices(db, client_cyber, client_read_only, client_it_user):
    from api.models.posture_exception import PostureException
    from api.models.settings import AuditLog
    from sqlalchemy import select
    tag = uuid.uuid4().hex[:8]
    t, a, b, s = await _devices(db, tag)
    until = (date.today() + timedelta(days=30)).isoformat()
    body = {"check": CHECK, "reason": "Hardware cannot be patched; isolated VLAN", "expires_on": until}
    assert (await client_read_only.post("/api/v1/posture-exceptions", json={**body, "scope": "all"})).status_code == 403
    assert (await client_it_user.post("/api/v1/posture-exceptions", json={**body, "scope": "all"})).status_code == 403
    for bad in ({"scope": "device"}, {"scope": "tag", "tag_id": str(uuid.uuid4())}, {"scope": "type"},
                {"scope": "device", "device_id": str(a.id), "expires_on": "2020-01-01"}, {"scope": "all", "reason": "short"},
                {"scope": "all", "check": "<script>"}, {"scope": "all", "extra": 1}):
        assert (await client_cyber.post("/api/v1/posture-exceptions", json={**body, **bad})).status_code == 422, bad

    before = await _state(client_cyber, a)
    assert before[0] is False and before[1] == 2 and "tags" in before[2] and before[2]["device_type"] == "workstation"

    r = await client_cyber.post("/api/v1/posture-exceptions", json={**body, "scope": "tag", "tag_id": str(t.id)})
    assert r.status_code == 201 and r.json()["where"] == f"Tag: app-{tag}"
    assert (await _state(client_cyber, a))[:2] == (True, 1) and (await _state(client_cyber, b))[0] is False

    r2 = await client_cyber.post("/api/v1/posture-exceptions", json={**body, "scope": "type", "device_type": "workstation"})
    assert r2.json()["where"] == "All workstations"
    assert (await _state(client_cyber, b))[0] is True and (await _state(client_cyber, s))[0] is False
    x = next(x for x in (await _state(client_cyber, a))[2]["signals"] if x["name"] == CHECK)
    assert x["excepted"]["scope"].startswith("Tag:")            # the narrowest one shows

    r3 = await client_cyber.post("/api/v1/posture-exceptions", json={**body, "scope": "device", "device_id": str(s.id)})
    assert (await _state(client_cyber, s))[0] is True
    await client_cyber.delete(f"/api/v1/posture-exceptions/{r3.json()['id']}")
    assert (await _state(client_cyber, s))[0] is False

    # turned off or ended: no longer applies
    await client_cyber.put(f"/api/v1/posture-exceptions/{r2.json()['id']}", json={"enabled": False})
    assert (await _state(client_cyber, b))[0] is False
    e = await db.get(PostureException, r.json()["id"])
    e.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    await db.commit()
    assert (await _state(client_cyber, a))[0] is False

    logged = (await db.execute(select(AuditLog.action).where(AuditLog.resource_type == "posture_exception"))).scalars().all()
    assert {"posture_exception.create", "posture_exception.update", "posture_exception.delete"} <= set(logged)
    listed = (await client_cyber.get("/api/v1/posture-exceptions")).json()["exceptions"]
    assert any(x["id"] == r.json()["id"] for x in listed)
    assert (await client_cyber.delete(f"/api/v1/posture-exceptions/{uuid.uuid4()}")).status_code == 404
