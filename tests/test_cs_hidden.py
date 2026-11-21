"""CrowdStrike hidden hosts: the shipper pulls them, and CTEM shows them as having CrowdStrike (contained or not)."""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))

import collector_common as cc  # noqa: E402
import collector_crowdstrike as cs  # noqa: E402

VIS, HID, OLD = "a" * 32, "b" * 32, "c" * 32


class FakeApi:
    def __init__(self, hidden_status=None):
        self.calls, self.hidden_status = [], hidden_status

    def call(self, method, path, body=None):
        self.calls.append(path)
        if path.startswith("/devices/queries/devices-scroll/"):
            return {"resources": [VIS], "meta": {"pagination": {"offset": ""}}}
        if path.startswith("/devices/queries/devices-hidden/"):
            if self.hidden_status:
                raise cc.HttpError(self.hidden_status, "no")
            off = int(path.rsplit("offset=", 1)[1])
            page = [[HID], [VIS]][off] if off < 2 else []   # VIS repeats: listed once only
            return {"resources": page, "meta": {"pagination": {"offset": off, "total": 2}}}
        if path == "/devices/entities/devices/v2":
            return {"resources": [{"device_id": i, "hostname": f"h-{i[0]}", "status": "contained",
                                   "last_seen": "2026-11-01T08:00:00Z"} for i in body["ids"]]}
        return {"resources": []}


def test_hidden_ids_page_by_offset_until_total():
    assert cs._hidden_ids(FakeApi()) == [HID, VIS]
    assert cs._hidden_ids(FakeApi(403)) == [] and cs._hidden_ids(FakeApi(404)) == []


def test_collect_ships_visible_then_hidden(monkeypatch):
    api = FakeApi()
    monkeypatch.setattr(cs, "_Falcon", lambda s, secret: api)
    monkeypatch.setattr(cs._Policies, "load", lambda self, rows: None)
    monkeypatch.setattr(cs._Logins, "load", lambda self, rows: {})
    batches = [b["devices"] for b in cs.collect({}, "x", {}) if "devices" in b]
    assert [(d["device_id"], d["hidden"]) for b in batches for d in b] == [(VIS, False), (HID, True)]
    assert batches[1][0]["last_seen"] == "2026-11-01T08:00:00Z" and batches[1][0]["status"] == "contained"


def test_device_reads_falcon_hidden_status():
    assert cs._device({"device_id": VIS, "host_hidden_status": "hidden"})["hidden"] is True
    assert cs._device({"device_id": VIS, "last_seen": "x" * 99})["last_seen"] is None


def test_schema_drops_an_unreadable_last_seen():
    from api.collector.schemas import CsDevice
    assert CsDevice(device_id=VIS, last_seen="not a time").last_seen is None
    assert CsDevice(device_id=VIS, last_seen="2026-11-01T08:00:00Z", hidden=True).last_seen.year == 2026


@pytest.mark.asyncio
async def test_hidden_contained_host_has_crowdstrike_and_is_contained(db):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.models.device import Device
    name = f"hid-{uuid.uuid4().hex[:8]}"
    await CrowdStrikeConnector({})._upsert([{"hostname": name, "device_id": HID, "status": "contained",
                                             "hidden": True, "last_seen": "2026-10-01T08:00:00Z"}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == name))).scalar_one()
    assert (dev.edr_vendor, dev.edr_active, dev.edr_contained, dev.edr_hidden) == ("crowdstrike", True, True, True)
    assert "crowdstrike" in dev.sources and dev.edr_device_id == HID
    assert dev.edr_last_seen.replace(tzinfo=None).isoformat().startswith("2026-10-01T08:00")   # Falcon's time, not now


@pytest.mark.asyncio
async def test_stale_hidden_copy_does_not_overwrite_the_live_host(db):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.models.device import Device
    name = f"dup-{uuid.uuid4().hex[:8]}"
    cs_ = CrowdStrikeConnector({})
    await cs_._upsert([{"hostname": name, "device_id": VIS, "status": "normal", "last_seen": "2026-11-19T08:00:00Z"}], [], db)
    await cs_._upsert([{"hostname": name, "device_id": OLD, "status": "contained", "hidden": True,
                        "last_seen": "2026-06-01T08:00:00Z"}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == name))).scalar_one()
    assert (dev.edr_device_id, dev.edr_contained, dev.edr_hidden) == (VIS, False, False)
    # the same host being hidden later is not a duplicate: it updates
    await cs_._upsert([{"hostname": name, "device_id": VIS, "status": "contained", "hidden": True,
                        "last_seen": "2026-11-20T08:00:00Z"}], [], db)
    await db.refresh(dev)
    assert (dev.edr_contained, dev.edr_hidden) == (True, True)


@pytest.mark.asyncio
async def test_inventory_hidden_filter(client_admin, db):
    from api.models.device import Device, DeviceType
    name = f"hf-{uuid.uuid4().hex[:8]}"
    db.add(Device(hostname=name, device_type=DeviceType.workstation, edr_hidden=True, edr_contained=True))
    await db.commit()
    r = (await client_admin.get("/api/v1/devices", params={"status": "edr_hidden", "q": name})).json()
    rows = r.get("devices") or r.get("items") or []
    assert [d["hostname"].lower() for d in rows] == [name] and rows[0]["edr_hidden"] is True
