"""Per-user data access rules (Admin > Users > Data access) and dashboards set to show all the data."""
from __future__ import annotations

import uuid

import pytest

from api.dashboards import catalog as cat

cat.load_metrics()


async def _tagged(db, name, tags):
    from api.core.device_tags import sync_tags
    from datetime import datetime, timezone

    from api.models.device import Device, DeviceType
    d = Device(hostname=name, device_type=DeviceType.server, last_seen=datetime.now(timezone.utc))
    db.add(d)
    await db.flush()
    await sync_tags(db, d.id, set(tags), tuple(sorted({t.split(":")[0] + ":" for t in tags})), "manual", {})
    await db.commit()
    return d


@pytest.mark.asyncio
async def test_a_person_sees_assets_where_their_owner_rule_matches(db, client_admin, client_it_user, it_user):
    from api.core import user_access
    n = uuid.uuid4().hex[:6]
    by_name = await _tagged(db, f"fudd-a-{n}", [f"exec_owner:Elmer Fudd{n}"])
    by_mail = await _tagged(db, f"fudd-b-{n}", [f"exec_owner:elmer.fudd{n}@acme.example"])
    other = await _tagged(db, f"bunny-{n}", [f"exec_owner:Bugs Bunny{n}"])
    url = f"/api/v1/admin/users/{it_user.id}/access"
    assert (await client_it_user.get(f"/api/v1/devices/{by_name.id}")).status_code == 404   # nothing yet
    rule = {"rules": [{"role": "executive_owner", "values": [f"elmer fudd{n}", f"ELMER.FUDD{n}@acme.example", f"Elmer Fudd{n}"]}]}
    r = (await client_admin.put(url, json=rule)).json()
    assert r["ok"] and r["rules"][0]["values"] == [f"ELMER.FUDD{n}@acme.example", f"elmer fudd{n}"]   # same value once
    assert r["tags"] == 2 and r["assets"] == 2
    user_access.forget()
    for d in (by_name, by_mail):
        assert (await client_it_user.get(f"/api/v1/devices/{d.id}")).status_code == 200
    assert (await client_it_user.get(f"/api/v1/devices/{other.id}")).status_code == 404
    names = {x["hostname"].lower() for x in (await client_it_user.get("/api/v1/devices", params={"q": n})).json()["devices"]}
    assert names == {f"fudd-a-{n}", f"fudd-b-{n}"}
    # an exact tag works too, and an empty list removes the rules
    assert (await client_admin.put(url, json={"rules": [{"role": "tag", "values": [f"exec_owner:Bugs Bunny{n}"]}]})).json()["assets"] == 1
    assert (await client_admin.put(url, json={"rules": []})).json()["rules"] == []
    user_access.forget()
    assert (await client_it_user.get(f"/api/v1/devices/{by_name.id}")).status_code == 404


@pytest.mark.asyncio
async def test_rules_are_checked_and_admin_only(client_admin, client_it_user, it_user):
    url = f"/api/v1/admin/users/{it_user.id}/access"
    assert (await client_admin.put(url, json={"rules": [{"role": "nope", "values": ["x"]}]})).json()["ok"] is False
    assert (await client_admin.put(url, json={"rules": [{"role": "executive_owner", "values": ["<b>x</b>"]}]})).status_code == 422
    assert (await client_admin.put(url, json={"rules": [{"role": "executive_owner", "values": ["  "]}]})).status_code == 422
    assert (await client_admin.put(url, json={"rules": [{"role": "Bad Key", "values": ["x"]}]})).status_code == 422
    assert (await client_admin.put(url, json={"rules": [], "extra": 1})).status_code == 422
    assert (await client_it_user.put(url, json={"rules": []})).status_code in (403, 404)
    assert (await client_it_user.get("/api/v1/admin/users/access/options")).status_code in (403, 404)
    opts = (await client_admin.get("/api/v1/admin/users/access/options")).json()
    assert [r["key"] for r in opts["roles"]][-2:] == ["tag", "all"] and any(r["key"] == "executive_owner" for r in opts["roles"])
    assert (await client_admin.get(f"/api/v1/admin/users/{uuid.uuid4()}/access")).status_code == 404


def _board(**kw):
    return {"name": f"ACME wide {uuid.uuid4().hex[:6]}", "visibility": "everyone", "share_roles": [],
            "widgets": [{"id": "w1", "metric": "assets.count", "viz": "kpi", "params": {}, "x": 0, "y": 0, "w": 3, "h": 2}], **kw}


@pytest.mark.asyncio
async def test_a_dashboard_can_show_everyone_all_the_data_only_as_an_admin_published_it(db, client_admin, client_it_user):
    await _tagged(db, f"hidden-{uuid.uuid4().hex[:6]}", ["env:prod"])
    d = (await client_admin.post("/api/v1/dashboards", json=_board())).json()
    url = f"/api/v1/dashboards/{d['id']}"
    assert (await client_admin.put(url, json=_board(data_scope="everything"))).json()["ok"]
    assert (await client_admin.post(f"{url}/publish")).json()["ok"]
    seen = (await client_it_user.get(url)).json()
    assert seen["data_scope"] == "everything" and seen["can_widen"] is False
    w = seen["widgets"]
    mine = (await client_it_user.post("/api/v1/dashboards/data", json={"widgets": w})).json()
    wide = (await client_it_user.post("/api/v1/dashboards/data", json={"widgets": w, "dashboard": d["id"]})).json()
    assert wide["everything"] and wide["data"]["w1"]["value"] > mine["data"]["w1"]["value"]
    # a widget the browser made up gets no wider view, even under the dashboard's name and a stored widget's id
    fake = [{"id": "w9", "metric": "assets.count", "viz": "kpi", "params": {}}]
    assert (await client_it_user.post("/api/v1/dashboards/data", json={"widgets": fake, "dashboard": d["id"]})).json()["data"]["w9"]["value"] \
        == mine["data"]["w1"]["value"]
    swapped = [{"id": "w1", "metric": "assets.new", "viz": "kpi", "params": {}}]
    got = (await client_it_user.post("/api/v1/dashboards/data", json={"widgets": swapped, "dashboard": d["id"]})).json()["data"]["w1"]
    assert got["value"] == wide["data"]["w1"]["value"]   # the stored widget ran, not the swapped one


@pytest.mark.asyncio
async def test_anyone_else_asks_and_cyber_approves_for_a_time(db, client_cyber, client_it_user, it_user):
    from datetime import datetime, timedelta, timezone

    from api.models.dashboard import Dashboard
    await _tagged(db, f"hidden-{uuid.uuid4().hex[:6]}", ["env:prod"])
    d = (await client_it_user.post("/api/v1/dashboards", json=_board(visibility="private"))).json()
    url = f"/api/v1/dashboards/{d['id']}"
    r = (await client_it_user.put(url, json=_board(visibility="private", data_scope="everything"))).json()
    assert r["ok"] and r["scope_pending"]                       # asked, not granted
    me = (await client_it_user.get(url)).json()
    assert me["data_scope"] == "viewer" and me["scope_request"]["by"] == it_user.username
    w = me["widgets"]
    ask = {"widgets": w, "dashboard": d["id"]}
    assert (await client_it_user.post("/api/v1/dashboards/data", json=ask)).json()["everything"] is False
    # cyber finds it (private, but waiting for them), can't approve a draft, then approves for a day once published
    listed = (await client_cyber.get("/api/v1/dashboards", params={"scope": "shared"})).json()["dashboards"]
    assert any(x["id"] == d["id"] and x["scope_request"] for x in listed)
    assert (await client_cyber.post(f"{url}/scope/approve", json={"days": 1})).json()["ok"] is False
    assert (await client_it_user.post(f"{url}/publish")).json()["ok"]
    assert (await client_it_user.post(f"{url}/scope/approve", json={"days": 1})).status_code == 404   # not theirs to decide
    ok = (await client_cyber.post(f"{url}/scope/approve", json={"days": 1})).json()
    assert ok["ok"] and ok["scope_until"]
    assert (await client_it_user.post("/api/v1/dashboards/data", json=ask)).json()["everything"] is True
    # past its end, it is each viewer's own access again
    row = await db.get(Dashboard, d["id"])
    await db.refresh(row)
    row.scope_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db.commit()
    assert (await client_it_user.post("/api/v1/dashboards/data", json=ask)).json()["everything"] is False
    # asked and approved again, then the owner changes it: back up for approval
    assert (await client_cyber.post(f"{url}/scope/approve", json={"days": 30})).status_code == 404   # private, nothing asked
    assert (await client_it_user.put(url, json=_board(visibility="private", data_scope="everything"))).json()["scope_pending"]
    assert (await client_it_user.post(f"{url}/publish")).json()["ok"]
    assert (await client_cyber.post(f"{url}/scope/approve", json={"days": 30})).json()["ok"]
    assert (await client_it_user.put(url, json=_board(visibility="private"))).json()["scope_pending"]
    after = (await client_it_user.get(url)).json()
    assert after["data_scope"] == "viewer" and after["scope_request"]["why"] == "changed after it was approved"
    assert (await client_cyber.post(f"{url}/scope/deny", json={})).json()["ok"]
    assert (await client_it_user.get(url)).json()["scope_request"] is None
    assert (await client_cyber.post(f"{url}/scope/approve", json={"days": 2})).status_code == 422   # only the offered spans


@pytest.mark.asyncio
async def test_wildcards_and_all_assets(db, client_admin, client_it_user, it_user):
    from api.core import user_access
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:6]
    acme = await _tagged(db, f"w-acme-{n}", [f"exec_owner:pat{n}@acme.example"])
    other = await _tagged(db, f"w-other-{n}", [f"exec_owner:pat{n}@other.example"])
    appd = await _tagged(db, f"w-app-{n}", [f"app:Claims{n}"])
    bare = Device(hostname=f"w-bare-{n}", device_type=DeviceType.server)   # no tags at all
    db.add(bare)
    await db.commit()
    url = f"/api/v1/admin/users/{it_user.id}/access"
    r = (await client_admin.put(url, json={"rules": [{"role": "executive_owner", "values": [f"*{n}@ACME.example"]},
                                                     {"role": "tag", "values": [f"app:claims{n[:3]}*"]}]})).json()
    assert r["ok"] and r["assets"] == 2
    user_access.forget()
    see = lambda d: client_it_user.get(f"/api/v1/devices/{d.id}")  # noqa: E731
    assert [(await see(d)).status_code for d in (acme, other, appd, bare)] == [200, 404, 200, 404]
    # a pattern is literal apart from * and ?
    assert user_access._hit("app:[x]", {"app:[x]"}) and not user_access._hit("app:x", {"app:[x]"})
    # complete visibility: every asset, tagged or not
    assert (await client_admin.put(url, json={"rules": [{"role": "all", "values": ["nope"]}]})).json()["ok"] is False
    r = (await client_admin.put(url, json={"rules": [{"role": "all", "values": ["*"]}]})).json()
    assert r["ok"] and r["all"] is True and r["assets"] >= 4
    user_access.forget()
    assert [(await see(d)).status_code for d in (acme, other, appd, bare)] == [200, 200, 200, 200]
    await client_admin.put(url, json={"rules": []})
    user_access.forget()
