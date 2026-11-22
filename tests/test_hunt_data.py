"""Threat hunting data: FDR events folded into fleet stacks, intel matching (and its alert), the stream, the API."""
from __future__ import annotations

import json
import sys
import uuid
from datetime import date
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))
import collector_cs_hunt as csh  # noqa: E402

A1, A2 = "1" * 32, "2" * 32
SHA = "ab" * 32


def test_fdr_events_fold_into_stacks():
    stacks = {}
    for aid in (A1, A2, A1):
        csh._fold(stacks, {"event_simpleName": "ProcessRollup2", "aid": aid, "timestamp": "1795400000000", "ImageFileName": r"\Device\x\acme.exe",
                           "SHA256HashData": SHA.upper(), "CommandLine": "acme.exe -q", "ParentBaseFileName": "explorer.exe"})
    csh._fold(stacks, {"event_simpleName": "DnsRequest", "aid": A1, "timestamp": "1795400000000", "DomainName": "Evil.Acme.Example."})
    csh._fold(stacks, {"event_simpleName": "NetworkConnectIP4", "aid": A1, "timestamp": "1795400000000", "RemoteAddressIP4": "203.0.113.9", "RemotePort": "443"})
    csh._fold(stacks, {"event_simpleName": "SensorHeartbeat", "aid": A1, "timestamp": "1795400000000"})
    csh._fold(stacks, {"event_simpleName": "DnsRequest", "aid": "nope", "timestamp": "1", "DomainName": "x"})
    rows = {r["kind"]: r for r in stacks.values()}
    assert set(rows) == {"process", "dns", "network"}
    p = rows["process"]
    assert p["hosts"] == [A1, A2] and p["events"] == 3 and p["sha256"] == SHA and p["fields"]["parent"] == "explorer.exe"
    assert rows["dns"]["value"] == "evil.acme.example" and rows["network"]["value"] == "203.0.113.9:443"


def test_stream_and_intel_records_are_read_safely():
    line = json.dumps({"metadata": {"offset": 42, "eventType": "RemoteResponseSessionStartEvent", "eventCreationTime": 1795400000000},
                       "event": {"Hostname": "ws-1", "UserName": "admin@acme.example", "Nested": {"x": 1}, "Ctl": "a\x07b"}}).encode()
    e = csh._stream_event(line, "0")
    assert e["offset"] == 42 and e["hostname"] == "ws-1" and "Nested" not in e["event"] and e["event"]["Ctl"] == "a b"
    assert csh._stream_event(b"not json", "0") is None
    i = csh._indicator({"indicator": "Evil.Acme.Example", "type": "domain", "malicious_confidence": "high", "actors": ["ACME SPIDER"],
                        "labels": [{"name": "C2"}], "last_updated": 1795400000})
    assert i["value"] == "evil.acme.example" and i["labels"] == ["C2"] and i["updated"].startswith("2026")


@pytest.mark.asyncio
async def test_intel_match_marks_the_stack_raises_once_and_the_api_shows_it(db, client_admin, client_it_user):
    from api.core import hunt_ingest as hi
    from api.models.alert_feed import FeedAlert
    from api.models.device import Device, DeviceType
    from api.models.hunt_data import HuntStack
    n = uuid.uuid4().hex[:6]
    dom = f"c2-{n}.acme.example"
    aid = uuid.uuid4().hex
    db.add(Device(hostname=f"ws-hunt-{n}", device_type=DeviceType.workstation, edr_device_id=aid))
    await hi.intel(db, [{"value": dom, "type": "domain", "confidence": "high", "actors": ["ACME SPIDER"]}])
    today = date.today().isoformat()
    key = uuid.uuid4().hex + uuid.uuid4().hex
    row = {"day": today, "kind": "dns", "key": key, "value": dom, "hosts": [aid], "events": 4,
           "first_seen": f"{today}T01:00:00+00:00", "last_seen": f"{today}T02:00:00+00:00"}
    await hi.stacks(db, [row])
    await hi.stacks(db, [{**row, "hosts": [aid, "9" * 32], "events": 1}])   # the next upload of the same day
    await db.commit()
    s = (await db.execute(select(HuntStack).where(HuntStack.key == key))).scalar_one()
    assert s.intel_hit and s.host_count == 2 and s.events == 5
    alerts = (await db.execute(select(FeedAlert).where(FeedAlert.key == f"intel_match:{today}:{key}"))).scalars().all()
    assert len(alerts) == 1 and alerts[0].event["actors"] == ["ACME SPIDER"]
    d = (await client_admin.get("/api/v1/hunt/data/stacks", params={"q": dom, "intel": "true"})).json()
    assert d["total"] == 1 and d["stacks"][0]["intel"] and d["stacks"][0]["hosts"] == 2
    assert (await client_admin.get("/api/v1/hunt/data/stacks", params={"q": dom, "rare": "true"})).json()["total"] == 1
    det = (await client_admin.get(f"/api/v1/hunt/data/stacks/{key}")).json()
    assert det["intel"]["actors"] == ["ACME SPIDER"] and any(h["hostname"] == f"ws-hunt-{n}" for h in det["hosts"])
    assert (await client_admin.get("/api/v1/hunt/data/stacks/notakey")).status_code == 404
    assert (await client_it_user.get("/api/v1/hunt/data/stacks")).status_code == 403


@pytest.mark.asyncio
async def test_stream_events_store_once_and_rtr_sessions_alert(db, client_admin):
    from api.core import hunt_ingest as hi
    from api.models.alert_feed import FeedAlert
    off = int(uuid.uuid4().int % 10**9)
    ev = {"partition": "0", "offset": off, "type": "RemoteResponseSessionStartEvent", "at": "2026-11-22T10:00:00+00:00",
          "hostname": "ws-rtr-1", "user": "admin@acme.example", "event": {"Hostname": "ws-rtr-1"}}
    assert await hi.stream_events(db, [ev]) == 1
    assert await hi.stream_events(db, [ev]) == 0
    await db.commit()
    assert (await db.execute(select(FeedAlert).where(FeedAlert.key == f"rtr_session:crowdstrike:0:{off}"))).scalar_one()
    r = (await client_admin.get("/api/v1/hunt/data/events", params={"q": "ws-rtr-1"})).json()
    assert r["total"] >= 1 and r["events"][0]["type"] == "RemoteResponseSessionStartEvent"
