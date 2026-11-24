"""Hiding an alert or a dashboard finding hides it for that person only."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest


@pytest.mark.asyncio
async def test_hiding_is_per_person(db, client_cyber, client_admin):
    from api.models.settings import AppSetting
    tag = uuid.uuid4().hex[:8]
    alert_id = f"threat_alert_test{tag}"
    db.add(AppSetting(key=alert_id, value=json.dumps({"id": tag, "title": f"Mandiant nltest {tag}", "source": "crowdstrike",
                                                      "hostname": f"hide-{tag}", "detected_at": datetime.now(timezone.utc).isoformat()})))
    issue_key = uuid.uuid4().hex[:16]
    watch = {"ran_at": datetime.now(timezone.utc).isoformat(), "note": "",
             "result": {"mode": "ai", "issues": [{"key": issue_key, "title": f"Recon {tag}", "severity": "high"}], "lookups": []}}
    from sqlalchemy import select
    have = (await db.execute(select(AppSetting).where(AppSetting.key == "hunt_watch"))).scalar_one_or_none()
    if have is None:
        db.add(AppSetting(key="hunt_watch", value=json.dumps(watch)))
    else:
        have.value = json.dumps(watch)
    await db.commit()

    def ids(r):
        return [a["id"] for a in r.json()["alerts"]]
    q = {"q": tag}
    assert alert_id in ids(await client_cyber.get("/api/v1/threat/alerts", params=q))
    r = await client_cyber.put("/api/v1/me/hidden", json={"kind": "alert", "id": alert_id, "hidden": True})
    assert r.status_code == 200
    mine = await client_cyber.get("/api/v1/threat/alerts", params=q)
    assert alert_id not in ids(mine) and mine.json()["hidden_count"] >= 1
    assert alert_id in ids(await client_cyber.get("/api/v1/threat/alerts", params={**q, "hidden": "show"}))
    assert alert_id in ids(await client_admin.get("/api/v1/threat/alerts", params=q))   # someone else still sees it

    assert (await client_cyber.put("/api/v1/me/hidden", json={"kind": "watch", "id": issue_key, "hidden": True})).status_code == 200
    w = (await client_cyber.get("/api/v1/hunt/watch")).json()
    assert issue_key not in [i.get("key") for i in w["result"]["issues"]] and w["hidden_count"] == 1
    assert issue_key in [i.get("key") for i in (await client_admin.get("/api/v1/hunt/watch")).json()["result"]["issues"]]
    shown = (await client_cyber.get("/api/v1/hunt/watch", params={"show_hidden": "true"})).json()["result"]["issues"]
    assert [i["hidden"] for i in shown if i["key"] == issue_key] == [True]

    # Unhide brings it back; bad input is refused
    await client_cyber.put("/api/v1/me/hidden", json={"kind": "alert", "id": alert_id, "hidden": False})
    assert alert_id in ids(await client_cyber.get("/api/v1/threat/alerts", params=q))
    for bad in ({"kind": "alert", "id": "not-an-alert-id-at-all", "hidden": True},
                {"kind": "device", "id": alert_id, "hidden": True},
                {"kind": "alert", "id": alert_id, "hidden": "yes"}):
        assert (await client_cyber.put("/api/v1/me/hidden", json=bad)).status_code in (400, 422)
    assert sorted((await client_cyber.get("/api/v1/me/hidden")).json()) == ["alert", "watch"]
    from sqlalchemy import delete
    await db.execute(delete(AppSetting).where(AppSetting.key.in_([alert_id, "hunt_watch"])))   # leave the shared db as found
    await db.commit()
