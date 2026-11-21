"""Dashboards: stale-directory widgets with any threshold, click-through, a trend from daily snapshots, per-widget
style, and AI that composes widgets and edits a dashboard on request."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.dashboards import catalog as cat


def test_style_is_cleaned():
    w = cat.clean_widget({"metric": "directory.stale_computers", "viz": "kpi", "params": {"days": 21},
                          "style": {"color": "blue", "warn_at": "10", "bad_at": 50, "higher_is_worse": False, "evil": "x"}})
    assert w["params"] == {"days": 21, "tools_quiet": "21"}   # by default, computers a scanner or EDR saw in 21 days stay off
    assert w["style"] == {"color": "blue", "warn_at": 10, "bad_at": 50, "higher_is_worse": False}
    assert cat.clean_widget({"metric": "directory.stale_computers", "style": {"color": "url(javascript:x)"}})["style"] == {}
    # thresholds only make sense on a single number
    assert cat.clean_widget({"metric": "directory.stale_trend", "style": {"color": "teal", "warn_at": 5}})["style"] == {"color": "teal"}


async def _ad(db, n, days_ago, tool_days=None, edr_days=None, prefix="ad"):
    from api.models.device import Device, DeviceType
    ago = lambda d: None if d is None else datetime.now(timezone.utc) - timedelta(days=d)  # noqa: E731
    d = Device(hostname=f"{prefix}{days_ago}-{n}.acme.example", device_type=DeviceType.workstation, ad_joined=True,
               ad_last_logon=ago(days_ago), last_seen=ago(tool_days), edr_last_seen=ago(edr_days),
               ad_dn="CN=x,OU=Win11,OU=Workstations,DC=acme,DC=example")
    db.add(d)
    return d


@pytest.mark.asyncio
async def test_stale_widgets_counts_clickthrough_and_trend(db, client_admin, admin_user):
    from api.dashboards.m_directory import record_snapshots
    n = uuid.uuid4().hex[:6]
    for age in (5, 25, 40, 120, None):
        await _ad(db, n, age)
    await db.commit()
    ctx = await cat.context(db, admin_user)
    v21 = await cat.REGISTRY["directory.stale_computers"].run(ctx, {"days": 21})
    v90 = await cat.REGISTRY["directory.stale_computers"].run(ctx, {"days": 90})
    assert v21["value"] - v90["value"] == 2 and v21["href"] == "/devices?ad_stale_days=21&ad_tools_quiet_days=21"   # the 25- and 40-day ones
    lst = await cat.REGISTRY["directory.stale_computers_list"].run(ctx, {"days": 90, "limit": 50})
    mine = [r for r in lst["rows"] if r[0].lower().endswith(n.lower())]
    assert {r[1] for r in mine} >= {"never"} and all(r[3].startswith("OU=Win11") for r in mine)
    # the card's link lands on exactly those devices
    r = (await client_admin.get("/api/v1/devices", params={"ad_stale_days": 90, "q": n})).json()
    assert {d["hostname"].lower()[:5] for d in r["devices"]} == {"ad120", "adnon"}
    # trend from the daily snapshot
    assert await record_snapshots(db) > 0
    t = await cat.REGISTRY["directory.stale_trend"].run(ctx, {"kind": "computers", "range": "30d"})
    assert [s["name"] for s in t["series"]] == ["21+ days", "30+ days", "90+ days"] and t["series"][0]["data"][-1] >= 3


@pytest.mark.asyncio
async def test_ai_composes_the_stale_dashboard_and_edits_on_request(db, client_admin, client_cyber, monkeypatch):
    calls = []

    class Fake:
        async def complete(self, prompt, **kw):
            calls.append(prompt)
            if "The dashboard now" in prompt:   # an edit: recolor the trend, keep the rest
                now = json.loads(prompt.split("The dashboard now", 1)[1].split(":\n", 1)[1].split("\n\nReturn", 1)[0])
                for w in now:
                    if w["metric"] == "directory.stale_trend":
                        w["style"] = {"color": "blue"}
                return json.dumps({"widgets": now, "note": "Made the trend blue."})
            return json.dumps({"name": "AD stale objects", "widgets": [
                {"metric": "directory.stale_computers", "viz": "kpi", "title": "90+", "params": {"days": 90}, "w": 4, "h": 2},
                {"metric": "directory.stale_computers", "viz": "kpi", "title": "30+", "params": {"days": 30}, "w": 4, "h": 2},
                {"metric": "directory.stale_computers", "viz": "kpi", "title": "21+", "params": {"days": 21}, "w": 4, "h": 2},
                {"metric": "directory.stale_trend", "viz": "line", "params": {"kind": "computers", "range": "90d"}, "w": 12, "h": 4}],
                "note": "Cards open the matching device list."})

    async def fake_ai(db):
        return Fake()
    monkeypatch.setattr("api.hunt.ai.get_ai", fake_ai)
    ask = ("This is a dashboard to provide the AD Infrastructure team with stale objects. Cards for 90, 30 and 21 days, "
           "a trend line, and clicking a card shows those items.")
    d = (await client_admin.post("/api/v1/dashboards/ai/dashboard", json={"text": ask})).json()
    assert [w["params"].get("days") for w in d["widgets"][:3]] == [90, 30, 21] and d["note"]
    assert "directory.stale_computers" in calls[0] and "warn_at" in calls[0]   # the catalog and style reach the AI
    made = (await client_admin.post("/api/v1/dashboards", json={"name": "AD stale", "visibility": "private",
                                                                "share_roles": [], "widgets": d["widgets"]})).json()
    e = (await client_admin.post(f"/api/v1/dashboards/ai/edit/{made['id']}", json={"text": "make the trend blue"})).json()
    trend = next(w for w in e["widgets"] if w["metric"] == "directory.stale_trend")
    assert trend["style"] == {"color": "blue"} and e["note"] == "Made the trend blue." and len(e["widgets"]) == 4
    # nothing saved yet, and someone who can't edit it can't ask
    saved = (await client_admin.get(f"/api/v1/dashboards/{made['id']}")).json()
    assert all(w.get("style", {}).get("color") != "blue" for w in saved["widgets"] if w["metric"] == "directory.stale_trend")
    r = await client_cyber.post(f"/api/v1/dashboards/ai/edit/{made['id']}", json={"text": "make it all red"})
    assert r.status_code == 404 or r.json().get("error")


@pytest.mark.asyncio
async def test_stale_leaves_out_computers_a_scanner_or_edr_still_sees(db, client_admin, admin_user):
    """An AD object with an old logon that a scanner or EDR heard from recently is alive, so it isn't stale."""
    n = uuid.uuid4().hex[:6]
    await _ad(db, n, 90, prefix="orph")                        # nothing else knows it: stale
    await _ad(db, n, 90, tool_days=5, prefix="scan")           # the scanner saw it 5 days ago: leave it off
    await _ad(db, n, 90, edr_days=3, prefix="edr")             # the EDR saw it 3 days ago: leave it off
    await _ad(db, n, 90, tool_days=60, edr_days=40, prefix="old")   # both quiet for weeks: stale
    await db.commit()
    ctx = await cat.context(db, admin_user)
    m = cat.REGISTRY["directory.stale_computers"]
    clean = lambda **p: {q.key: q.clean(p.get(q.key)) for q in m.params}  # noqa: E731
    on = await m.run(ctx, clean(days=44))                      # 21 days of tool silence by default
    off = await m.run(ctx, clean(days=44, tools_quiet="off"))
    assert off["value"] - on["value"] == 2 and "ad_tools_quiet_days=21" in on["href"]
    r = (await client_admin.get("/api/v1/devices", params={"ad_stale_days": 44, "ad_tools_quiet_days": 21, "q": n})).json()
    assert {d["hostname"].lower()[:3] for d in r["devices"]} == {"orp", "old"}
    lst = await cat.REGISTRY["directory.stale_computers_list"].run(ctx, {"days": 44, "tools_quiet": "21", "limit": 50})
    names = {row[0].lower()[:3] for row in lst["rows"] if row[0].lower().endswith(n)}
    assert names == {"orp", "old"} and lst["columns"][2] == "Last scanner or EDR contact"


@pytest.mark.asyncio
async def test_ai_edit_builds_on_unsaved_work_and_earlier_requests(client_admin, monkeypatch):
    seen = []

    class Fake:
        async def complete(self, prompt, **kw):
            seen.append(prompt)
            now = json.loads(prompt.split("The dashboard now", 1)[1].split(":\n", 1)[1].split("\n\nReturn", 1)[0])
            for w in now:
                w["style"] = {"color": "red"}
            return json.dumps({"widgets": now, "note": "Made it red."})

    async def fake_ai(db):
        return Fake()
    monkeypatch.setattr("api.hunt.ai.get_ai", fake_ai)
    made = (await client_admin.post("/api/v1/dashboards", json={"name": "AD stale", "visibility": "private", "share_roles": [],
                                                                "widgets": []})).json()
    unsaved = [{"id": "abc123", "metric": "directory.stale_computers", "viz": "kpi", "params": {"days": 44}, "x": 0, "y": 0, "w": 4, "h": 2}]
    r = (await client_admin.post(f"/api/v1/dashboards/ai/edit/{made['id']}", json={
        "text": "make the 44-day card red", "widgets": unsaved, "history": ["cards for 44, 30 and 21 days"]})).json()
    assert r["widgets"][0]["params"]["days"] == 44 and r["widgets"][0]["style"] == {"color": "red"}
    assert "cards for 44, 30 and 21 days" in seen[0] and '"days":44' in seen[0]
    too_many = {"text": "again please", "history": ["one more time"] * 9}
    assert (await client_admin.post(f"/api/v1/dashboards/ai/edit/{made['id']}", json=too_many)).status_code == 422
