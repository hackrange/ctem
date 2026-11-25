"""Suppress similar: a hunt finding's alerts grouped into signatures (detection, process, the process that started it),
and accepting them so the same alerts stop raising findings. A watch finding left with no unaccepted alert goes."""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import delete, select

ROW = {"alert": "ApplicationAbusePreventionRemoteMonitoringAndManagement", "source": "crowdstrike",
       "process": "\\Device\\HarddiskVolume3\\Users\\x\\code-tunnel.exe", "parent": "Code.exe", "sha256": "a" * 64}


def _result(tag):
    rows = [{**ROW, "host": f"WS1-{tag}"}, {**ROW, "host": f"WS2-{tag}", "sha256": "b" * 64}, {**ROW, "host": f"WS1-{tag}"}]
    other = [{"alert": "VolumeShadowSnapshotDeleted", "source": "crowdstrike", "process": "setup.exe", "host": f"SRV-{tag}"}]
    return {"lookups": [{"rows": rows}, {"rows": other}, {"rows": [{"user": "x"}]}],
            "issues": [{"title": f"Remote tunnel {tag}", "lookups": [1], "severity": "high", "confidence": "high"},
                       {"title": f"Shadow copies {tag}", "lookups": [2], "severity": "critical", "confidence": "high"},
                       {"title": f"AI story {tag}", "lookups": [3], "severity": "high", "confidence": "high"}]}


def test_signatures_group_by_detection_process_and_parent():
    from api.routes.hunt_suppress import signatures
    r = _result("t")
    s = signatures(r, r["issues"][0])
    assert len(s) == 1 and s[0]["process"] == "code-tunnel.exe" and s[0]["parent"] == "Code.exe" and s[0]["alerts"] == 3
    assert s[0]["hosts"] == ["WS1-t", "WS2-t"] and s[0]["hashes"] == ["a" * 64, "b" * 64]
    assert signatures(r, r["issues"][2]) == []                       # raised from other evidence


def test_a_parent_narrows_the_match():
    from api.core.alert_allow import covers_row
    from api.models.alert_allow import AlertAllow
    r = AlertAllow(title=ROW["alert"], source="crowdstrike", process="code-tunnel.exe", parent="code.exe")
    assert covers_row([r], {**ROW, "host": "h"}) is r
    assert covers_row([r], {**ROW, "host": "h", "parent": "powershell.exe"}) is None   # same name, started by something else
    assert covers_row([r], {**ROW, "host": "h", "process": "evil.exe"}) is None


@pytest.mark.asyncio
async def test_suppressing_accepts_the_signature_and_clears_the_watch(db, client_cyber, client_read_only):
    from api.hunt.watch import WATCH_KEY
    from api.models.alert_allow import AlertAllow
    from api.models.settings import AppSetting
    tag = uuid.uuid4().hex[:6]
    await db.execute(delete(AppSetting).where(AppSetting.key == WATCH_KEY))
    db.add(AppSetting(key=WATCH_KEY, value=json.dumps({"ran_at": "x", "result": _result(tag)})))
    await db.commit()
    try:
        assert (await client_read_only.get("/api/v1/hunt/suppress/watch/0")).status_code == 403
        assert (await client_cyber.get("/api/v1/hunt/suppress/watch/9")).status_code == 404
        assert (await client_cyber.get("/api/v1/hunt/suppress/bad%20src/0")).status_code == 404
        opts = (await client_cyber.get("/api/v1/hunt/suppress/watch/0")).json()
        assert [s["process"] for s in opts["signatures"]] == ["code-tunnel.exe"]
        body = {"signatures": [0], "reason": "VS Code tunnels are approved", "expires_on": "2099-01-01"}
        assert (await client_cyber.post("/api/v1/hunt/suppress/watch/0", json=body)).status_code == 422   # past a year
        from datetime import date, timedelta
        body["expires_on"] = (date.today() + timedelta(days=90)).isoformat()
        assert (await client_cyber.post("/api/v1/hunt/suppress/watch/0", json={**body, "reason": "short"})).status_code == 422
        assert (await client_cyber.post("/api/v1/hunt/suppress/watch/2", json=body)).status_code == 409    # no alerts in it
        r = (await client_cyber.post("/api/v1/hunt/suppress/watch/0", json=body)).json()
        assert r == {"created": 1, "already": 0, "watch_removed": 1}
        a = (await db.execute(select(AlertAllow).where(AlertAllow.title == ROW["alert"], AlertAllow.reason == body["reason"]))).scalars().all()
        assert [(x.process, x.parent, x.hostname, x.sha256) for x in a] == [("code-tunnel.exe", "Code.exe", None, None)]
        await db.refresh((await db.execute(select(AppSetting).where(AppSetting.key == WATCH_KEY))).scalar_one())
        left = json.loads((await db.execute(select(AppSetting.value).where(AppSetting.key == WATCH_KEY))).scalar_one())["result"]["issues"]
        assert [i["title"] for i in left] == [f"Shadow copies {tag}", f"AI story {tag}"]
        # the shadow-copy finding, narrowed to its host and its file: one entry per host; no hash to pin
        assert (await client_cyber.post("/api/v1/hunt/suppress/watch/0", json={**body, "pin_hash": True})).status_code == 422
        r = (await client_cyber.post("/api/v1/hunt/suppress/watch/0", json={**body, "hosts_only": True})).json()
        assert r["created"] == 1 and r["watch_removed"] == 1
        assert (await db.execute(select(AlertAllow.hostname).where(AlertAllow.title == "VolumeShadowSnapshotDeleted",
                                                                   AlertAllow.reason == body["reason"]))).scalar_one() == f"SRV-{tag}"
    finally:
        await db.execute(delete(AlertAllow).where(AlertAllow.reason == "VS Code tunnels are approved"))
        await db.execute(delete(AppSetting).where(AppSetting.key == WATCH_KEY))
        await db.commit()
