"""Tests for CMDB list, sync, and export endpoints."""
from __future__ import annotations

import uuid
import pytest


@pytest.mark.asyncio
async def test_cmdb_list_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/cmdb")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_cmdb_list_read_only_denied(client_read_only):
    r = await client_read_only.get("/api/v1/cmdb")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_cmdb_list_cyber_allowed(client_cyber):
    r = await client_cyber.get("/api/v1/cmdb")
    assert r.status_code == 200
    d = r.json()
    assert "records" in d
    assert "total" in d
    assert "servicenow_enabled" in d


@pytest.mark.asyncio
async def test_cmdb_list_includes_device(client_cyber, db):
    from api.models.device import Device, DeviceType
    dev = Device(id=str(uuid.uuid4()), hostname="cmdb-test-host",
                 device_type=DeviceType.server, is_internet_exposed=False)
    db.add(dev)
    await db.commit()

    r = await client_cyber.get("/api/v1/cmdb", params={"q": "cmdb-test-host"})
    assert r.status_code == 200
    hostnames = [rec["hostname"] for rec in r.json()["records"]]
    assert "CMDB-TEST-HOST" in hostnames


@pytest.mark.asyncio
async def test_cmdb_record_shape(client_cyber, db):
    from api.models.device import Device, DeviceType
    dev = Device(id=str(uuid.uuid4()), hostname="shape-test-host",
                 os="Ubuntu", os_version="22.04",
                 device_type=DeviceType.server, is_internet_exposed=False)
    db.add(dev)
    await db.commit()

    r = await client_cyber.get("/api/v1/cmdb", params={"q": "shape-test-host"})
    assert r.status_code == 200
    rec = next((x for x in r.json()["records"] if x["hostname"] == "SHAPE-TEST-HOST"), None)
    assert rec is not None
    assert rec["ip_address"] is None          # never exposed in list view
    assert rec["os_name"] == "Ubuntu"
    assert "risk_grade" in rec


@pytest.mark.asyncio
async def test_cmdb_sync_requires_auth(client_no_auth):
    r = await client_no_auth.post("/api/v1/cmdb/sync")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_cmdb_sync_no_integration(client_cyber):
    # No ServiceNow integration configured -- should 422
    r = await client_cyber.post("/api/v1/cmdb/sync")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_cmdb_export_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/cmdb/export")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_cmdb_export_shape(client_cyber):
    r = await client_cyber.get("/api/v1/cmdb/export")
    assert r.status_code == 200
    d = r.json()
    assert "configuration_items" in d
    assert "export_time" in d
    assert d["source"] == "open-ctem"


@pytest.mark.asyncio
async def test_cmdb_total_and_paging_go_past_200(client_cyber, db):
    from api.models.device import Device, DeviceType
    tag = uuid.uuid4().hex[:8]
    for i in range(230):
        db.add(Device(hostname=f"cmdbpage{tag}-{i:03d}.acme.example", device_type=DeviceType.workstation))
    await db.commit()
    first = (await client_cyber.get("/api/v1/cmdb", params={"q": f"cmdbpage{tag}", "limit": 200})).json()
    assert first["total"] == 230 and len(first["records"]) == 200
    last = (await client_cyber.get("/api/v1/cmdb", params={"q": f"cmdbpage{tag}", "limit": 200, "offset": 200})).json()
    names = {r["hostname"] for r in first["records"]} | {r["hostname"] for r in last["records"]}
    assert len(last["records"]) == 30 and len(names) == 230
    assert first["records"][0]["fqdn"] == f"CMDBPAGE{tag.upper()}-000.ACME.EXAMPLE"
    assert (await client_cyber.get("/api/v1/cmdb", params={"limit": 500})).status_code == 422
