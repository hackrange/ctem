"""Dashboard builder: drafts and publishing, themes, starter dashboards and stock widgets, the new chart types and
transparency, the risk and asset widgets, and the device list filters their cards link to."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.dashboards import catalog as cat
from api.dashboards import fleet, presets

cat.load_metrics()


def _body(**kw):
    return {"name": f"ACME board {uuid.uuid4().hex[:6]}", "visibility": "everyone", "share_roles": [],
            "widgets": [{"metric": "assets.count", "viz": "kpi", "params": {}, "x": 0, "y": 0, "w": 3, "h": 2}], **kw}


@pytest.mark.asyncio
async def test_draft_publish_discard_and_unpublish(client_cyber, client_it_user):
    d = (await client_cyber.post("/api/v1/dashboards", json=_body(theme="ocean"))).json()
    url = f"/api/v1/dashboards/{d['id']}"
    me = (await client_cyber.get(url)).json()
    assert me["published"] is False and me["theme"] == "ocean"
    assert (await client_it_user.get(url)).status_code == 404               # a draft: only the owner (and admins)
    assert (await client_cyber.post(f"{url}/publish")).json()["ok"]
    assert (await client_it_user.get(url)).json()["widgets"][0]["metric"] == "assets.count"
    # edits to a published dashboard are a draft: viewers keep the published version
    edit = _body(widgets=[{"metric": "risk.score", "viz": "gauge"}], theme="neon")
    assert (await client_cyber.put(url, json=edit)).json()["draft"] is True
    seen = (await client_it_user.get(url)).json()
    assert seen["widgets"][0]["metric"] == "assets.count" and seen["theme"] == "ocean" and "draft" not in seen
    mine = (await client_cyber.get(url)).json()
    assert mine["has_draft"] and mine["draft"]["widgets"][0]["metric"] == "risk.score" and mine["draft"]["theme"] == "neon"
    assert (await client_it_user.post(f"{url}/publish")).status_code == 404   # only the owner publishes
    assert (await client_cyber.post(f"{url}/discard")).json()["ok"]
    assert "draft" not in (await client_cyber.get(url)).json()
    await client_cyber.put(url, json=edit)
    await client_cyber.post(f"{url}/publish")
    assert (await client_it_user.get(url)).json()["widgets"][0]["metric"] == "risk.score"
    assert (await client_cyber.post(f"{url}/unpublish")).json()["ok"]
    assert (await client_it_user.get(url)).status_code == 404
    assert (await client_cyber.post("/api/v1/dashboards", json=_body(theme="hotpink"))).status_code == 422


@pytest.mark.asyncio
async def test_starter_dashboards_and_stock_widgets(client_admin, client_it_user):
    c = (await client_admin.get("/api/v1/dashboards/catalog")).json()
    keys = {t["key"] for t in c["templates"]}
    assert {"risk_overview", "remediation", "coverage", "vuln_trends"} <= keys and c["themes"][0] == "default"
    assert all(p["metric"] in cat.REGISTRY for p in c["presets"]) and len(c["presets"]) > 30
    # every stock widget survives cleaning unchanged in its chart type
    for k, p in presets.PRESETS.items():
        w = presets.widget(k)
        assert w and w["viz"] == p["viz"], k
    made = (await client_admin.post("/api/v1/dashboards", json={**_body(widgets=[]), "template": "risk_overview"})).json()
    d = (await client_admin.get(f"/api/v1/dashboards/{made['id']}")).json()
    assert len(d["widgets"]) >= 8 and d["theme"] == "default" and not d["published"]
    assert all(w["x"] + w["w"] <= cat.GRID_COLS for w in d["widgets"])
    # people who can't see threats data don't get the alerts widget in their catalog
    assert "alerts" not in {p["key"] for p in (await client_it_user.get("/api/v1/dashboards/catalog")).json()["presets"]}
    assert (await client_admin.post("/api/v1/dashboards", json={**_body(widgets=[]), "template": "nope"})).status_code == 422


def test_new_chart_types_and_transparency_are_cleaned():
    w = cat.clean_widget({"metric": "risk.score", "viz": "gauge", "style": {"opacity": "55", "color": "teal"}})
    assert w["viz"] == "gauge" and w["style"] == {"color": "teal", "opacity": 55}
    assert cat.clean_widget({"metric": "risk.vuln_scatter", "viz": "bubble"})["viz"] == "bubble"
    assert cat.clean_widget({"metric": "coverage.tagged", "viz": "pie"})["viz"] == "pie"
    assert cat.clean_widget({"metric": "vuln.trend", "viz": "stacked"})["viz"] == "stacked"
    assert cat.clean_widget({"metric": "risk.score", "style": {"opacity": 5}})["style"] == {}   # too faint to read
    assert cat.clean_widget({"metric": "risk.score", "style": {"opacity": 100}})["style"] == {}


def test_resample_and_headline():
    x = [f"2026-11-{d:02d}" for d in range(2, 16)]   # Mon 2 Nov .. Sun 15 Nov: two whole weeks
    labels, (lvl, flow) = fleet.resample(x, [list(range(14)), [1] * 14], "week", ["last", "sum"])
    assert labels == ["2026-11-02", "2026-11-09"] and lvl == [6, 13] and flow == [7, 7]
    assert fleet.change([100] + [None] * 29 + [80], "open findings") == "20.0% decrease in open findings over the last month"
    assert fleet.delta(110, 100)["pct"] == 10.0 and fleet.delta(5, None) is None


@pytest.mark.asyncio
async def test_asset_and_risk_widgets_and_their_card_links(db, client_admin, admin_user):
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:6]
    now = datetime.now(timezone.utc)
    win = Device(hostname=f"w-{n}.acme.example", device_type=DeviceType.server, os="Microsoft Windows Server 2022",
                 sources=",ldap,", edr_active=True, last_seen=now, risk_score=99.9, open_findings=3)
    lin = Device(hostname=f"l-{n}.acme.example", device_type=DeviceType.server, os="Ubuntu Linux 22.04",
                 sources=",rapid7_insightvm,", edr_active=False, last_seen=now - timedelta(days=90))
    db.add_all([win, lin])
    await db.commit()
    ctx = await cat.context(db, admin_user)
    run = lambda m, **p: cat.REGISTRY[m].run(ctx, {q.key: q.clean(p.get(q.key)) for q in cat.REGISTRY[m].params})  # noqa: E731
    v = await run("assets.count", device_type="server", os_family="windows", missing="scanner", seen="active_30d")
    assert v["value"] >= 1 and "os_family=windows" in v["href"] and "missing=scanner" in v["href"] and "active_days=30" in v["href"]
    # the card's link lands on the same devices
    r = (await client_admin.get("/api/v1/devices", params={"q": n, "os_family": "windows", "missing": "scanner", "active_days": 30})).json()
    assert [d["hostname"].lower()[:2] for d in r["devices"]] == ["w-"]
    r = (await client_admin.get("/api/v1/devices", params={"q": n, "os_family": "linux", "missing": "edr"})).json()
    assert [d["hostname"].lower()[:2] for d in r["devices"]] == ["l-"]
    assert (await client_admin.get("/api/v1/devices", params={"os_family": "'; drop"})).status_code == 422
    fams = {i["name"] for i in (await run("assets.by_os", seen="any"))["items"]}
    assert {"Windows", "Linux"} <= fams
    score = await run("risk.score")
    assert score["max"] == 100 and score["value"] is not None
    tagged = await run("coverage.tagged", by="owner", seen="any")
    assert tagged["center"]["value"] >= 2 and "tagged by any owner" in tagged["headline"]
    scatter = await run("assets.risk_scatter", limit=50)
    assert any(p[3].lower().startswith(f"w-{n}") for g in scatter["groups"] for p in g["points"])
    over = await run("assets.over_time", range="30d", bucket="week")
    assert over["series"][0]["name"] == "On-prem" and len(over["x"]) >= 4
    from api.dashboards import snapshots
    assert await snapshots.record(db) >= 8
    trend = await run("coverage.trend", range="30d", bucket="day")
    assert trend["series"][0]["data"][-1] is not None


@pytest.mark.asyncio
async def test_widget_filters_on_tags_roles_sources_and_my_access(db, client_admin, admin_user):
    from sqlalchemy import select

    from api.core.device_tags import sync_tags
    from api.dashboards import filters as flt
    from api.models.device import Device, DeviceType
    from api.models.tag import GroupTagAccess, Tag
    n = uuid.uuid4().hex[:6]
    a = Device(hostname=f"fa-{n}.acme.example", device_type=DeviceType.server, sources=",crowdstrike,ldap,", edr_active=True)
    b = Device(hostname=f"fb-{n}.acme.example", device_type=DeviceType.server, sources=",rapid7_insightvm,")
    c = Device(hostname=f"fc-{n}.acme.example", device_type=DeviceType.workstation, sources=",rapid7_insightvm,crowdstrike,")
    db.add_all([a, b, c])
    await db.flush()
    await sync_tags(db, a.id, {f"exec_owner:Pat_{n}", f"env:prod{n}"}, ("exec_owner:", "env:"), "manual", {})
    await sync_tags(db, b.id, {f"exec_owner:Pat_{n}"}, ("exec_owner:",), "manual", {})
    await sync_tags(db, c.id, {f"env:prod{n}"}, ("env:",), "manual", {})
    await db.commit()
    ctx = await cat.context(db, admin_user)
    mine = {"field": "tag", "op": "starts_with", "value": f"f{n}"}   # never matches: tags, not hostnames

    async def count(filters, match="all"):
        w = cat.clean_widget({"metric": "assets.count", "params": {"seen": "any"}, "filters": filters, "filter_match": match})
        assert len(w["filters"]) == len([f for f in filters if f is not mine]) or filters == [mine]
        hosts = (await db.execute(select(Device.hostname).where(await flt.where(db, w["filters"], w["filter_match"], admin_user),
                                                                Device.hostname.like(f"%-{n}.acme.example")))).scalars().all()
        out = await cat.evaluate(ctx, w)
        return sorted(h[:2] for h in hosts), out
    owner = {"field": "role", "role": "executive_owner", "op": "is", "value": f"pat {n}"}   # tidied value, any case
    assert (await count([owner]))[0] == ["fa", "fb"]
    assert (await count([owner, {"field": "source", "op": "is", "value": "crowdstrike"}]))[0] == ["fa"]
    assert (await count([{"field": "tag", "op": "is", "value": f"env:prod{n}"},
                         {"field": "source", "op": "is_not", "value": "crowdstrike"}]))[0] == []
    hosts, out = await count([{"field": "tag", "op": "is", "value": f"env:prod{n}"}, owner], "any")
    assert hosts == ["fa", "fb", "fc"] and out["value"] >= 3
    hosts, out = await count([{"field": "tag", "op": "is", "value": f"env:prod{n}"}])
    assert f"tag=env%3Aprod{n}" in out["href"]   # the card's link keeps the tag
    # anything not on the allow-lists is dropped
    bad = cat.clean_widget({"metric": "assets.count", "filters": [{"field": "sql", "op": "is", "value": "x"},
                                                                    {"field": "source", "op": "is", "value": "evil"},
                                                                    {"field": "tag", "op": "is", "value": "<b>"},
                                                                    {"field": "role", "role": "Bad Key!", "op": "any"}]})
    assert bad["filters"] == []
    assert cat.clean_widget({"metric": "threats.count", "filters": [owner]})["filters"] == []   # not device based
    # "my access": the admin's grants (none yet) and assignments: nothing of these three
    assert (await count([{"field": "access", "op": "mine"}]))[0] == []
    tag = (await db.execute(select(Tag).where(Tag.name == f"env:prod{n}"))).scalar_one()
    db.add(GroupTagAccess(role_name="admin", tag_id=tag.id))
    await db.commit()
    assert (await count([{"field": "access", "op": "mine"}]))[0] == ["fa", "fc"]


@pytest.mark.asyncio
async def test_ai_asks_when_unsure_and_uses_the_answer(client_admin, monkeypatch):
    prompts = []

    class Fake:
        async def complete(self, prompt, **kw):
            prompts.append(prompt)
            if "The person already answered" not in prompt:
                return '{"question": "Which tools count as seeing a computer?", "options": ["Scanner and EDR", "EDR only"]}'
            return '{"name": "AD stale", "widgets": [{"metric": "directory.stale_computers", "viz": "kpi", "params": {"days": 44}}]}'

    async def fake_ai(db):
        return Fake()
    monkeypatch.setattr("api.hunt.ai.get_ai", fake_ai)
    ask = {"text": "Stale AD computers at 44, 30 and 21 days"}
    q = (await client_admin.post("/api/v1/dashboards/ai/dashboard", json=ask)).json()
    assert q["question"].startswith("Which tools") and q["options"] == ["Scanner and EDR", "EDR only"] and "widgets" not in q
    assert "do not guess" in prompts[0]
    r = (await client_admin.post("/api/v1/dashboards/ai/dashboard", json={**ask, "answers": [
        "Which tools count as seeing a computer? -> Scanner and EDR"]})).json()
    assert r["widgets"][0]["params"]["days"] == 44 and "-> Scanner and EDR" in prompts[1]


@pytest.mark.asyncio
async def test_widget_csv_export_is_formula_safe(db, client_admin):
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:6]
    db.add(Device(hostname=f"=cmd-{n}", device_type=DeviceType.server, risk_score=99.99, open_findings=5))
    await db.commit()
    r = await client_admin.post("/api/v1/dashboards/export", json={"widget": {"metric": "devices.riskiest", "viz": "table",
                                                                               "title": "Riskiest", "params": {"limit": 25}}})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"] and "Riskiest" in r.headers["content-disposition"]
    body = r.text
    assert body.splitlines()[0] == '"Device","Grade","Score","Open","KEV"' and f"\"'=cmd-{n}" in body.lower()
    chart = await client_admin.post("/api/v1/dashboards/export", json={"widget": {"metric": "assets.by_os", "viz": "bar"}})
    assert chart.text.splitlines()[0] == '"Name","Value"'
    assert (await client_admin.post("/api/v1/dashboards/export", json={"widget": {"metric": "nope"}})).status_code == 422
