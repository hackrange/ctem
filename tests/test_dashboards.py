"""Dashboards: sharing and edit rights, the admin view, Favorites, widget cleaning, per-viewer data, AI drafts."""
from __future__ import annotations

import json
import uuid

import pytest

from api.dashboards import catalog as cat

cat.load_metrics()


def _body(**kw):
    return {"name": f"ACME board {uuid.uuid4().hex[:6]}", "visibility": "private", "share_roles": [],
            "widgets": [{"metric": "devices.count", "viz": "kpi", "params": {"status": "contained"}, "x": 0, "y": 0, "w": 3, "h": 2}],
            **kw}


@pytest.mark.asyncio
async def test_private_until_shared_and_only_the_owner_edits(client_cyber, client_it_user):
    d = (await client_cyber.post("/api/v1/dashboards", json=_body())).json()
    url = f"/api/v1/dashboards/{d['id']}"
    assert (await client_it_user.get(url)).status_code == 404          # not shared: looks absent
    assert (await client_cyber.put(url, json=_body(visibility="roles", share_roles=["it_user"]))).json()["ok"]
    got = (await client_it_user.get(url)).json()
    assert got["can_edit"] is False and got["widgets"][0]["metric"] == "devices.count"
    assert (await client_it_user.put(url, json=_body())).status_code == 404
    assert (await client_it_user.delete(url)).status_code == 404
    mine = (await client_it_user.post(f"{url}/copy")).json()           # copying gives them their own
    assert (await client_it_user.put(f"/api/v1/dashboards/{mine['id']}", json=_body(name="Mine now"))).json()["ok"]
    shared = (await client_it_user.get("/api/v1/dashboards", params={"scope": "shared"})).json()["dashboards"]
    assert d["id"] in {x["id"] for x in shared}


@pytest.mark.asyncio
async def test_admin_sees_every_dashboard_others_cannot_ask(client_it_user, client_admin):
    d = (await client_it_user.post("/api/v1/dashboards", json=_body())).json()
    assert (await client_it_user.get("/api/v1/dashboards", params={"scope": "all"})).status_code == 404
    every = (await client_admin.get("/api/v1/dashboards", params={"scope": "all"})).json()
    assert d["id"] in {x["id"] for x in every["dashboards"]} and every["is_admin"]


@pytest.mark.asyncio
async def test_favorites_follow_what_you_can_see(client_cyber, client_it_user):
    d = (await client_cyber.post("/api/v1/dashboards", json=_body(visibility="everyone"))).json()
    assert (await client_it_user.put(f"/api/v1/favorites/dashboard/{d['id']}")).json()["starred"]
    favs = (await client_it_user.get("/api/v1/favorites")).json()["favorites"]
    assert [f["url"] for f in favs] == [f"/dashboards/{d['id']}"]
    await client_cyber.put(f"/api/v1/dashboards/{d['id']}", json=_body(visibility="private"))
    assert (await client_it_user.get("/api/v1/favorites")).json()["favorites"] == []   # unshared: it drops out
    assert (await client_it_user.put(f"/api/v1/favorites/dashboard/{d['id']}")).status_code == 404
    assert (await client_it_user.put(f"/api/v1/favorites/device/{d['id']}")).status_code == 422   # kind allow-list


def test_widgets_are_cleaned_to_the_catalog():
    assert cat.clean_widget({"metric": "sql.drop_tables"}) is None
    w = cat.clean_widget({"metric": "vuln.trend", "viz": "<script>", "title": "<b>x</b> trend", "x": 99, "w": -4,
                          "params": {"range": "10y", "severity": "critical", "evil": 1}, "id": "a b;"})
    assert w["viz"] == "line" and w["title"] == "bx/b trend" and w["x"] == cat.GRID_COLS - 1 and w["w"] == 1
    assert w["params"]["range"] == "90d" and w["params"]["severity"] == "critical" and "evil" not in w["params"]
    assert w["id"] == ""


@pytest.mark.asyncio
async def test_catalog_hides_threats_from_it_users(client_it_user, client_admin):
    theirs = {m["id"] for m in (await client_it_user.get("/api/v1/dashboards/catalog")).json()["metrics"]}
    admins = {m["id"] for m in (await client_admin.get("/api/v1/dashboards/catalog")).json()["metrics"]}
    assert "threats.count" in admins and "threats.count" not in theirs and "devices.count" in theirs


@pytest.mark.asyncio
async def test_widget_numbers_are_the_viewers_own(client_it_user, client_admin, it_user, db):
    from api.models.device import Device, DeviceAssignment, DeviceType
    tag = uuid.uuid4().hex[:6]
    devs = [Device(hostname=f"wd-{tag}-{i}", device_type=DeviceType.workstation, edr_contained=True) for i in range(3)]
    db.add_all(devs)
    await db.flush()
    db.add(DeviceAssignment(device_id=devs[0].id, user_id=it_user.id))
    await db.commit()
    w = {"id": "w1", "metric": "devices.count", "params": {"status": "contained"}}
    theirs = (await client_it_user.post("/api/v1/dashboards/data", json={"widgets": [w]})).json()["data"]["w1"]
    every = (await client_admin.post("/api/v1/dashboards/data", json={"widgets": [w]})).json()["data"]["w1"]
    assert theirs["value"] == 1 and every["value"] >= 3
    blocked = (await client_it_user.post("/api/v1/dashboards/data", json={"widgets": [{"id": "t", "metric": "threats.count"}]})).json()
    assert "error" in blocked["data"]["t"]


@pytest.mark.asyncio
async def test_ai_drafts_stay_inside_the_viewers_catalog(client_it_user, client_admin, monkeypatch):
    import api.hunt.ai as hunt_ai

    class FakeAI:
        async def complete(self, *a, **kw):
            return json.dumps({"metric": "threats.count", "viz": "kpi", "title": "Open alerts", "params": {"range": "7d"},
                               "note": "Counted open alerts only."})

    async def fake(_db):
        return FakeAI()
    monkeypatch.setattr(hunt_ai, "get_ai", fake)
    r = (await client_admin.post("/api/v1/dashboards/ai/widget", json={"text": "how many open alerts this week"})).json()
    assert r["widget"]["metric"] == "threats.count" and r["widget"]["params"]["range"] == "7d" and r["note"]
    r = (await client_it_user.post("/api/v1/dashboards/ai/widget", json={"text": "how many open alerts this week"})).json()
    assert "error" in r and "widget" not in r

    async def none(_db):
        return None
    monkeypatch.setattr(hunt_ai, "get_ai", none)
    assert (await client_admin.post("/api/v1/dashboards/ai/dashboard", json={"text": "weekly patching review"})).json() == {"available": False}
