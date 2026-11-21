"""Last seen = the freshest sign of life from any tool (scanner, EDR heartbeat, AD logon), shown and sorted."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.routes import device_query as dq


def _now():
    return datetime.now(timezone.utc)


def test_freshest_picks_the_most_recent_tool():
    from api.models.device import Device
    d = Device(hostname="x", last_seen=_now() - timedelta(days=3), edr_last_seen=_now() - timedelta(days=1),
               ad_last_logon=(_now() - timedelta(days=9)).replace(tzinfo=None))
    at, by, each = dq.freshest(d)
    assert by == "EDR" and (_now() - at).days == 1 and set(each) == {"Scanner", "EDR", "AD logon"}
    assert dq.freshest(Device(hostname="y")) == (None, None, {})


@pytest.mark.asyncio
async def test_device_list_shows_and_sorts_by_the_freshest(db, client_admin):
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:8]
    old_scan_fresh_edr = Device(hostname=f"ls-a-{n}", device_type=DeviceType.workstation,
                                last_seen=_now() - timedelta(days=30), edr_last_seen=_now() - timedelta(hours=2))
    fresh_scan = Device(hostname=f"ls-b-{n}", device_type=DeviceType.workstation, last_seen=_now() - timedelta(days=2))
    never = Device(hostname=f"ls-c-{n}", device_type=DeviceType.workstation)
    db.add_all([old_scan_fresh_edr, fresh_scan, never])
    await db.commit()
    resp = await client_admin.get("/api/v1/devices", params={"q": n, "sort": "last_seen", "order": "desc", "limit": 200})
    assert resp.status_code == 200, resp.text
    r = resp.json()
    mine = [d for d in r["devices"] if d["hostname"].lower().endswith(n)]
    assert [d["hostname"].lower()[:4] for d in mine] == ["ls-a", "ls-b", "ls-c"]
    assert mine[0]["last_seen_by"] == "EDR" and mine[0]["scan_last_seen"] and mine[2]["last_seen"] is None
