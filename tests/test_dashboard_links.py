"""Every dashboard row that links to a list lands on that list already filtered to the same assets it counts."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

import pytest

from api.dashboards import catalog as cat

cat.load_metrics()


def _page_params(href: str) -> dict:
    """What the Devices page sends for a link: the link's own filters, and Hosts unless the link names an asset kind."""
    p = dict(parse_qsl(urlsplit(href).query))
    p.setdefault("asset", "hosts")
    if p["asset"] == "all":   # the All tab sends no asset kind
        del p["asset"]
    return p


async def _seed(db):
    """One asset for every row kind, so the comparisons are of real counts, not 0 = 0."""
    import uuid
    from datetime import datetime, timedelta, timezone

    from api.models.device import Device, DeviceType
    now, t = datetime.now(timezone.utc), uuid.uuid4().hex[:6]
    db.add_all([
        Device(hostname=f"srv-{t}", device_type=DeviceType.server, last_seen=now, sources=",rapid7_insightvm,"),       # no owner, no EDR
        Device(hostname=f"ws-{t}", device_type=DeviceType.workstation, last_seen=now, edr_vendor="crowdstrike",
               edr_last_seen=now - timedelta(days=10), sources=",crowdstrike,"),                                        # EDR quiet
        Device(hostname=f"old-{t}", device_type=DeviceType.server, last_seen=now - timedelta(days=45)),                  # unseen
        Device(hostname=f"shop-{t}.acme.example", device_type=DeviceType.website, last_seen=now, is_internet_exposed=True),
        Device(hostname=f"acme/app-{t}", device_type=DeviceType.code_repository, last_seen=now),
    ])
    await db.commit()


@pytest.mark.parametrize("area", ["vulnerabilities", "endpoint", "identity", "code", "web", "ownership"])
async def test_scorecard_rows_and_their_lists_agree(db, admin_user, client_admin, area):
    await _seed(db)
    ctx = await cat.context(db, admin_user)
    out = await cat.REGISTRY["posture.scorecard"].run(ctx, {"area": area})
    assert out["hrefs"], area
    checked = []
    for row, href in zip(out["rows"], out["hrefs"]):
        assert href and href != "/devices" and href != "/vulns", (row[0], href)            # never an unfiltered list
        assert not href.startswith(("/threats", "/directory/users")), href                   # pages that don't exist
        count = row[1]["v"] if isinstance(row[1], dict) else row[1]
        if href.startswith("/devices?") and "with_findings" not in href:
            r = await client_admin.get("/api/v1/devices", params={**_page_params(href), "limit": 1})
            assert r.status_code == 200, (href, r.text)
            assert r.json()["total"] == count, (area, row[0], href, r.json()["total"], count)
            checked.append((row[0], count))
    if area in ("endpoint", "ownership"):
        assert any(c for _, c in checked), checked   # real assets were compared


async def test_new_filters_are_accepted_and_bounded(client_admin):
    for q in ("without=technical_owner", "unseen_days=30", "edr_quiet_days=7&compute=1", "with_findings=1", "internet=1", "kev=1"):
        assert (await client_admin.get(f"/api/v1/devices?{q}&limit=1")).status_code == 200, q
    for bad in ("without=anything", "unseen_days=0", "edr_quiet_days=99999"):
        assert (await client_admin.get(f"/api/v1/devices?{bad}")).status_code == 422, bad
    assert (await client_admin.get("/api/v1/vulns?past_sla=true&limit=1")).status_code == 200
    assert (await client_admin.get("/api/v1/directory/users?stale_days=90&limit=1")).status_code == 200
    assert (await client_admin.get("/api/v1/directory/users?stale_days=0")).status_code == 422
