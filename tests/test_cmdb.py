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

    r = await client_cyber.get("/api/v1/cmdb")
    assert r.status_code == 200
    hostnames = [rec["hostname"] for rec in r.json()["records"]]
    assert "cmdb-test-host" in hostnames


@pytest.mark.asyncio
async def test_cmdb_record_shape(client_cyber, db):
    from api.models.device import Device, DeviceType
    dev = Device(id=str(uuid.uuid4()), hostname="shape-test-host",
                 os="Ubuntu", os_version="22.04",
                 device_type=DeviceType.server, is_internet_exposed=False)
    db.add(dev)
    await db.commit()

    r = await client_cyber.get("/api/v1/cmdb")
    assert r.status_code == 200
    rec = next((x for x in r.json()["records"] if x["hostname"] == "shape-test-host"), None)
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
