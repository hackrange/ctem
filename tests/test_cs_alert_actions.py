"""CrowdStrike alert updates from CTEM: only cyber and admin, only four Falcon actions, sent directly or by the shipper
(checked again on the box), and the alert page reads well even for alerts saved without their detail."""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))
import collector_common as cc  # noqa: E402
import collector_cs_actions as csx  # noqa: E402

from tests.test_collector import _KEY, _auth, _code_from, _profile  # noqa: E402

CLIENT = "a" * 32


def _cid():
    return f"{uuid.uuid4().hex}:ind:{uuid.uuid4().hex}:{uuid.uuid4().int % 10**12}-10381-1"


async def _alert(db, cid=None, **extra):
    from api.models.settings import AppSetting
    cid = cid or _cid()
    key = f"threat_alert_{cid}"
    db.add(AppSetting(key=key, is_sensitive=False, value=json.dumps({"source": "crowdstrike", "id": cid, "status": "new",
                                                                     "title": "TamperAttempt", **extra})))
    await db.commit()
    return key


# ── the update itself ──────────────────────────────────────────────────────────

def test_an_update_is_only_the_four_allowed_actions_and_the_box_checks_it_again():
    b = csx.body(["cid:ind:a:1"], status="closed", classification="false_positive", comment="Admin tool", who="jdoe")
    names = [a["name"] for a in b["action_parameters"]]
    assert names == ["remove_tags_by_prefix", "add_tag", "update_status", "append_comment"]
    assert b["action_parameters"][1]["value"] == "ctem_false_positive" and "jdoe via open-ctem" in b["action_parameters"][3]["value"]
    assert csx.check(b) is b
    for bad in ({**b, "extra": 1}, {**b, "action_parameters": [{"name": "unassign", "value": ""}]},
                {**b, "action_parameters": [{"name": "update_status", "value": "deleted"}]},
                {**b, "action_parameters": [{"name": "add_tag", "value": "anything"}]},
                {**b, "action_parameters": [{"name": "remove_tags_by_prefix", "value": ""}]},
                {**b, "composite_ids": ["bad id; rm"]}, {**b, "composite_ids": []},
                {**b, "action_parameters": [{"name": "append_comment", "value": "a\x00b"}]}):
        with pytest.raises(ValueError):
            csx.check(bad)
    for kw in ({"status": "deleted"}, {"classification": "malware"}, {}, {"comment": "x" * 1001}, {"comment": "a\x07"}):
        with pytest.raises(ValueError):
            csx.body(["cid:ind:a:1"], who="jdoe", **kw)
    assert csx.body(["c:1"], comment="line one\nline two", who="jdoe")["action_parameters"][0]["name"] == "append_comment"


def test_turning_alert_updates_on_needs_a_yes_on_the_box_and_off_changes_nothing():
    from api.collector.profile import dest_digest, validate_settings
    base = validate_settings("crowdstrike", {"client_id": CLIENT})
    on = validate_settings("crowdstrike", {"client_id": CLIENT, "alert_updates": "on"})
    assert base["alert_updates"] is None
    assert dest_digest("crowdstrike", base) == cc.dest_digest("crowdstrike", base)   # existing approvals stay valid
    assert dest_digest("crowdstrike", on) != dest_digest("crowdstrike", base)
    assert dest_digest("crowdstrike", on) == cc.dest_digest("crowdstrike", on)       # server and box agree
    with pytest.raises(Exception):
        validate_settings("crowdstrike", {"client_id": CLIENT, "alert_updates": "yes"})


def test_how_an_update_goes():
    from api.collector.profile import dest_digest
    from api.core.cs_alert_actions import decide
    on = {"client_id": CLIENT, "alert_updates": "on"}
    prof = lambda s: SimpleNamespace(id="p1", modules={"crowdstrike": {"integration_id": "i-ship", "settings": s}})  # noqa: E731
    direct = SimpleNamespace(id="i-direct", is_enabled=True, config={"client_id": CLIENT, "client_secret": "s"})
    owned = SimpleNamespace(id="i-ship", is_enabled=True, config={})
    assert decide([], [], {})["via"] is None
    assert "Turn on Alert updates" in decide([owned], [prof({"client_id": CLIENT})], {})["why"]
    assert "approve" in decide([owned], [prof(on)], {"p1": SimpleNamespace(approved={})})["why"]
    ok = decide([owned], [prof(on)], {"p1": SimpleNamespace(approved={"crowdstrike": dest_digest("crowdstrike", on)})})
    assert ok == {"via": "shipper", "integration_id": "i-ship", "why": None}
    assert decide([owned, direct], [prof(on)], {})["via"] == "direct"
    assert decide([SimpleNamespace(id="i-x", is_enabled=False, config=direct.config)], [], {})["via"] is None


# ── who may update, and the queue the shipper takes from ─────────────────────────

@pytest.mark.asyncio
async def test_only_cyber_and_admin_can_update_and_bad_input_is_refused(db, client_read_only, client_it_user, client_cyber, monkeypatch):
    from api.core import cs_alert_actions as act
    key = await _alert(db)
    body = {"ids": [key], "status": "closed"}
    assert (await client_read_only.post("/api/v1/threat/alerts/update", json=body)).status_code == 403
    assert (await client_it_user.post("/api/v1/threat/alerts/update", json=body)).status_code == 403
    for bad in ({"ids": [key], "status": "deleted"}, {"ids": [key], "classification": "malware"}, {"ids": []},
                {"ids": [key], "status": "closed", "extra": 1}, {"ids": ["threat_alert_x y"], "status": "closed"}):
        assert (await client_cyber.post("/api/v1/threat/alerts/update", json=bad)).status_code == 422
    assert (await client_cyber.post("/api/v1/threat/alerts/update", json={"ids": [f"threat_alert_{_cid()}"], "status": "closed"})).status_code == 404
    from api.models.settings import AppSetting
    s1 = f"threat_alert_s1_{uuid.uuid4().hex}"
    db.add(AppSetting(key=s1, is_sensitive=False, value=json.dumps({"source": "sentinelone", "id": "x"})))
    await db.commit()
    r = await client_cyber.post("/api/v1/threat/alerts/update", json={"ids": [key, s1], "status": "closed"})
    assert r.status_code == 400 and "Only CrowdStrike" in r.json()["detail"]   # another tool's alert never goes to Falcon

    async def nothing(db):
        return {"via": None, "integration_id": None, "why": "No CrowdStrike integration or shipper can send updates."}
    monkeypatch.setattr(act, "route", nothing)
    r = await client_cyber.post("/api/v1/threat/alerts/update", json=body)
    assert r.status_code == 409 and "No CrowdStrike" in r.json()["detail"]
    assert (await client_cyber.post("/api/v1/threat/alerts/update", json={"ids": [key]})).status_code == 409


async def _shipper(client, client_admin, alert_updates="on"):
    settings = {"client_id": CLIENT, **({"alert_updates": alert_updates} if alert_updates else {})}
    p = await _profile(client_admin, {"crowdstrike": {"settings": settings}})
    code = _code_from((await client_admin.post(f"/api/v1/collectors/{p['id']}/installer", json={"allowed_cidrs": []})).text)
    tok = (await client.post("/api/v1/collector/enroll", json={"code": code, "hostname": "server001", "agent_version": "1.8.0",
                                                                "public_key": _KEY[1]})).json()["token"]
    p = (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()
    return p["modules"]["crowdstrike"]["integration_id"], tok


@pytest.mark.asyncio
async def test_a_shipper_update_is_queued_sent_once_and_its_answer_shows(db, client, client_admin, client_cyber, monkeypatch):
    from api.core import cs_alert_actions as act
    from api.models.alert_action import AlertAction
    from api.models.settings import AppSetting, AuditLog
    iid, tok = await _shipper(client, client_admin)
    key = await _alert(db)

    async def via_shipper(db):
        return {"via": "shipper", "integration_id": iid, "why": None}
    monkeypatch.setattr(act, "route", via_shipper)
    r = await client_cyber.post("/api/v1/threat/alerts/update",
                                json={"ids": [key], "status": "closed", "classification": "true_positive", "comment": "Contained and reimaged"})
    assert r.status_code == 200 and r.json()["via"] == "shipper" and r.json()["updates"][0]["state"] == "queued"
    # The key is longer than the audit log's resource id column (Postgres refused it and the update failed): it's
    # recorded as its UUIDv5, and the alert is named in the detail
    assert len(key) > 36
    audit = (await db.execute(select(AuditLog).where(AuditLog.action == "threat.alert_update",
                                                     AuditLog.resource_id == str(uuid.uuid5(uuid.NAMESPACE_URL, key))))).scalar_one()
    assert len(audit.resource_id) == 36 and key.removeprefix("threat_alert_") in audit.detail

    got = (await client.get(f"/api/v1/collector/alert-actions/{iid}", headers=_auth(tok))).json()["actions"]
    mine = [a for a in got if a["body"]["composite_ids"] == [key.removeprefix("threat_alert_")]]
    assert len(mine) == 1 and csx.check(mine[0]["body"])
    again = (await client.get(f"/api/v1/collector/alert-actions/{iid}", headers=_auth(tok))).json()["actions"]
    assert mine[0]["id"] not in [a["id"] for a in again]   # sent once, never handed out twice

    other_iid, other_tok = await _shipper(client, client_admin)
    assert (await client.get(f"/api/v1/collector/alert-actions/{iid}", headers=_auth(other_tok))).status_code == 404
    assert (await client.post(f"/api/v1/collector/alert-actions/{other_iid}/results", headers=_auth(other_tok),
                              json={"results": [{"id": mine[0]["id"], "ok": True}]})).json()["recorded"] == 0
    r = await client.post(f"/api/v1/collector/alert-actions/{iid}/results", headers=_auth(tok),
                          json={"results": [{"id": mine[0]["id"], "ok": True}]})
    assert r.json()["recorded"] == 1
    fresh = {"populate_existing": True}
    a = (await db.execute(select(AlertAction).where(AlertAction.id == mine[0]["id"]).execution_options(**fresh))).scalar_one()
    assert a.state == "done" and a.params["comment"] == "Contained and reimaged"
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key).execution_options(**fresh))).scalar_one()
    assert json.loads(row.value)["status"] == "closed"

    d = (await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": key})).json()
    assert d["can_update"]["via"] == "shipper" and d["updates"][0]["state"] == "done" and d["updates"][0]["classification"] == "true_positive"


@pytest.mark.asyncio
async def test_a_shipper_without_alert_updates_gets_nothing(client, client_admin):
    iid, tok = await _shipper(client, client_admin, alert_updates=None)
    assert (await client.get(f"/api/v1/collector/alert-actions/{iid}", headers=_auth(tok))).status_code == 404
    assert (await client.post(f"/api/v1/collector/alert-actions/{iid}/results", headers=_auth(tok), json={"results": []})).status_code == 404


class _Resp:
    def __init__(self, code, data=None):
        self.status_code, self._data = code, data or {}

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


@pytest.mark.asyncio
@pytest.mark.parametrize("code,state", [(200, "done"), (403, "failed")])
async def test_a_direct_update_answers_at_once(db, client_cyber, monkeypatch, code, state):
    from api.core import cs_alert_actions as act
    from api.core import ssrf
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AppSetting
    cfg = IntegrationConfig(vendor=Vendor.crowdstrike, name=f"cs-{uuid.uuid4().hex[:6]}", is_enabled=True,
                            config={"client_id": CLIENT, "client_secret": "s"})
    db.add(cfg)
    await db.commit()
    key = await _alert(db)
    sent = []

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, data=None):
            return _Resp(200, {"access_token": "t"})

        async def patch(self, url, headers=None, json=None):
            sent.append((url, json))
            return _Resp(code)

    async def direct(db):
        return {"via": "direct", "integration_id": str(cfg.id), "why": None}
    monkeypatch.setattr(act, "route", direct)
    monkeypatch.setattr(ssrf, "safe_client", lambda **kw: Client())
    r = await client_cyber.post("/api/v1/threat/alerts/update", json={"ids": [key], "status": "in_progress"})
    assert r.status_code == 200 and r.json()["updates"][0]["state"] == state
    assert sent[0][0] == "https://api.crowdstrike.com/alerts/entities/alerts/v3" and csx.check(sent[0][1])
    q = select(AppSetting).where(AppSetting.key == key).execution_options(populate_existing=True)
    status = json.loads((await db.execute(q)).scalar_one().value)["status"]
    assert status == ("in_progress" if code == 200 else "new")
    if code == 403:
        assert "Alerts: Write" in r.json()["updates"][0]["error"]


def test_the_shipper_sends_each_update_once_and_refuses_what_it_does_not_allow():
    good = csx.body(["c:1"], status="closed", who="jdoe")
    items = [{"id": str(uuid.uuid4()), "body": good}, {"id": str(uuid.uuid4()), "body": {**good, "extra": 1}},
             {"id": str(uuid.uuid4()), "body": good}, {"id": "not-a-uuid", "body": good}]
    writes, posted = [], []

    class Falcon:
        def write(self, method, path, body):
            writes.append((method, path))
            if len(writes) == 2:
                raise cc.HttpError(403, {})

    class Ctem:
        def call(self, method, path, body=None, retries=0):
            if method == "GET":
                return {"actions": items}
            posted.append(body)

    out = csx.run(Falcon(), Ctem(), "iid", say=lambda m: None)
    assert writes == [("PATCH", csx.PATH)] * 2
    assert [r["ok"] for r in out] == [True, False, False]
    assert "refused it" in out[1]["error"] and "Alerts: Write" in out[2]["error"]
    assert posted == [{"results": out}]


# ── reading the alert ────────────────────────────────────────────────────────────

def test_an_alert_saved_without_a_title_is_named_for_what_it_did_and_repeats_are_one_line():
    from api.core.threat_timeline import timeline
    from api.core.threat_view import normalize
    desc = "A process attempted to modify files used for Falcon sensor dynamic configuration. " * 2
    a = normalize("threat_alert_x", {"source": "crowdstrike", "technique": "Disable or Modify Tools", "description": desc})
    assert a["title"] == "Disable or Modify Tools" and a["description"] == desc.strip()
    rel = [{"id": f"r{i}", "title": "Disable or Modify Tools", "severity": "high", "detected_at": f"2026-11-2{i}T00:00:00"}
           for i in range(4)] + [{"id": "z", "title": "Other", "severity": "low", "detected_at": "2026-11-21T05:00:00"}]
    ev = [e for e in timeline({**a, "detected_at": "2026-11-20T00:00:00"}, {}, rel) if e["kind"] == "related"]
    assert len(ev) == 2 and "4 times" in ev[0]["text"] and ev[0]["title"].startswith("Other alerts on this host")


def test_an_alert_saved_without_a_link_gets_one_like_the_others():
    from api.core.cs_alert_actions import console_link
    links = ["https://falcon.crowdstrike.com/activity-v2/detections/aa:ind:bb:1-2-3?_cid=g0abc"]
    assert console_link("cc:ind:dd:4-5-6", links) == "https://falcon.crowdstrike.com/activity-v2/detections/cc:ind:dd:4-5-6?_cid=g0abc"
    assert console_link("cc:ind:dd:4", ["https://evil.example/activity-v2/detections/x"]) is None
    assert console_link("cc:ind:dd:4", []) is None


def test_an_audit_entry_always_fits_its_column():
    from api.models.settings import AuditLog
    long = "threat_alert_" + "a" * 120
    assert AuditLog(action="x", resource_id=long).resource_id == str(uuid.uuid5(uuid.NAMESPACE_URL, long))
    assert AuditLog(action="x", resource_id="short-id").resource_id == "short-id"
    assert AuditLog(action="x", resource_id=None).resource_id is None
