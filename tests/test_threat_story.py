"""An alert's story and attack map: alerts tied by host, user or process tree, repeats folded into one step, a map of
what ran and what it did, and a light AI read that only ever sees names and MITRE data."""
from __future__ import annotations

import json
import uuid

import pytest

from tests.test_threat_detail import RAW


def test_the_map_runs_host_user_process_chain_then_what_it_did():
    from api.core.cs_alert import csa
    from api.core.threat_graph import build
    s = csa.summary(RAW)
    alert = {"hostname": "DESKTOP001", "title": s["title"], "tactic": "Credential Access", "technique": "OS Credential Dumping"}
    g = build(alert, csa.clean(s["detail"]))
    ids = [n["id"] for n in g["nodes"]]
    assert ids[:5] == ["host", "user", "grandparent", "parent", "process"]
    hit = next(n for n in g["nodes"] if n["id"] == "process")
    assert hit["hit"] and ["Command line", "procdump.exe -ma lsass.exe out.dmp"] in hit["facts"]
    kinds = {n["kind"] for n in g["nodes"]}
    assert {"action", "quarantine", "network", "dns"} <= kinds
    assert all(e["from"] in ids and e["to"] in ids for e in g["edges"])
    cols = {n["id"]: n["col"] for n in g["nodes"]}
    assert all(cols[e["from"]] < cols[e["to"]] for e in g["edges"])   # left to right, in the order things happened
    # only the summary: host, then the detection
    bare = build({"hostname": "H1", "title": "Disable or Modify Tools", "description": "tamper"}, {})
    assert [n["kind"] for n in bare["nodes"]] == ["host", "detection"] and bare["edges"][0]["label"] == "Detected"


def test_many_of_one_kind_fold_into_a_more_box():
    from api.core.threat_graph import MAX_PER_KIND, build
    detail = {"process": {"filename": "x.exe"}, "dns": [{"domain": f"d{i}.example"} for i in range(MAX_PER_KIND + 5)]}
    g = build({"hostname": "H"}, detail)
    dns = [n for n in g["nodes"] if n["kind"] == "dns"]
    assert len(dns) == MAX_PER_KIND + 1 and dns[-1]["label"] == "+5 more DNS lookups"


def test_story_steps_fold_repeats_and_say_why_each_is_tied_in():
    from api.core.threat_graph import steps
    me = {"id": "a0", "title": "Tamper", "severity": "high", "hostname": "H1", "detected_at": "2026-11-20T10:00:00", "status": "new"}
    rel = [{"id": f"r{i}", "title": "Tamper", "severity": "high", "hostname": "H1", "detected_at": f"2026-11-2{i}T09:00:00",
            "status": "closed", "why": "same host"} for i in range(1, 4)]
    rel += [{"id": "u1", "title": "Credential dump", "severity": "critical", "hostname": "H2", "detected_at": "2026-11-21T00:00:00",
             "status": "new", "why": "same user"}]
    out = steps(me, rel)
    assert len(out) == 2
    mine = next(s for s in out if s["current"])
    assert mine["count"] == 4 and mine["id"] == "a0" and mine["why"] == "this alert" and mine["status"] == "open"
    assert mine["first"] == "2026-11-20T10:00:00" and mine["last"] == "2026-11-23T09:00:00"
    other = next(s for s in out if not s["current"])
    assert other["why"] == "same user" and other["hostname"] == "H2"


def test_the_user_key_ties_a_person_not_a_machine_account():
    from api.integrations.crowdstrike import alert_user_key
    a = alert_user_key({"user": {"name": "jdoe", "domain": "ACME"}})
    assert a and a == alert_user_key({"user": {"name": "ACME\\JDoe"}}) and "jdoe" not in a
    assert alert_user_key({"user": {"name": "PRDHOST00$"}}) is None
    assert alert_user_key({"user": {"name": "anything", "sid": "S-1-5-18"}}) is None
    assert alert_user_key({"user": {"name": "SYSTEM"}}) is None and alert_user_key({}) is None


@pytest.mark.asyncio
async def test_alerts_for_the_same_user_on_another_host_join_the_story(db, client_cyber):
    from api.core.cs_alert import csa
    from api.integrations.base import get_connector
    tag = uuid.uuid4().hex[:8]
    here = csa.summary({**RAW, "composite_id": f"cid:ind:{tag}:1", "aggregate_id": f"agg:{tag}:1"})
    there = csa.summary({**RAW, "composite_id": f"cid:ind:{tag}:2", "aggregate_id": f"agg:{tag}:2", "display_name": "LateralMove",
                         "device": {**RAW["device"], "hostname": f"SRV-{tag}", "device_id": "e" * 32}})
    stranger = csa.summary({**RAW, "composite_id": f"cid:ind:{tag}:3", "aggregate_id": f"agg:{tag}:3", "user_name": f"other{tag}",
                            "device": {**RAW["device"], "hostname": f"OTHER-{tag}", "device_id": "f" * 32}})
    stranger["detail"]["user"] = {"name": f"other{tag}"}
    for x in (here, there):
        x["device"]["hostname"] = x["device"]["hostname"] if x is there else f"WS-{tag}"
    await get_connector("crowdstrike", {"client_id": "x", "client_secret": "y"})._cache_threats([here, there, stranger], db)
    a = (await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": f"threat_alert_cid:ind:{tag}:1"})).json()
    tied = {r["id"]: r["why"] for r in a["related"] if tag in r["id"]}
    assert tied == {f"threat_alert_cid:ind:{tag}:2": "same user"}
    assert any(s["why"] == "same user" and s["hostname"] == f"SRV-{tag}" for s in a["steps"])
    assert a["graph"]["nodes"][0]["label"] == f"WS-{tag}" and "user_key" not in json.dumps(a["graph"])
    g = (await client_cyber.get("/api/v1/threat/alerts/graph", params={"id": f"threat_alert_cid:ind:{tag}:2"})).json()
    assert g["hostname"] == f"SRV-{tag}" and g["graph"]["nodes"]


@pytest.mark.asyncio
async def test_the_ai_read_sees_names_and_mitre_only_and_is_saved(db, client_cyber, client_read_only, monkeypatch):
    from api.core.cs_alert import csa
    from api.hunt import ai as hunt_ai
    from api.integrations.base import get_connector
    tag = uuid.uuid4().hex[:8]
    await get_connector("crowdstrike", {"client_id": "x", "client_secret": "y"})._cache_threats(
        [csa.summary({**RAW, "composite_id": f"cid:ind:{tag}:1"})], db)
    key = f"threat_alert_cid:ind:{tag}:1"
    prompts = []

    class AI:
        async def complete(self, prompt, **kw):
            prompts.append(prompt)
            return json.dumps({"summary": "procdump dumped LSASS <b>", "verdict": "likely_malicious", "why": ["a", "b", "c", "d"],
                               "next_steps": ["Reset jdoe's password"], "extra": "ignored"})

    async def ai_on(db):
        return AI()
    monkeypatch.setattr(hunt_ai, "get_ai", ai_on)
    assert (await client_read_only.post("/api/v1/threat/alerts/explain", json={"id": key})).status_code == 403
    r = (await client_cyber.post("/api/v1/threat/alerts/explain", json={"id": key})).json()
    assert r["read"]["verdict"] == "likely_malicious" and len(r["read"]["why"]) == 3 and "extra" not in r["read"]
    sent = prompts[0]
    assert "procdump.exe" in sent and "Credential" in sent
    for secret in ("-ma lsass", "jdoe", "192.0.2.10", "203.0.113.7", "files.acme-bad.example", "a" * 64, "HarddiskVolume3"):
        assert secret not in sent
    again = (await client_cyber.post("/api/v1/threat/alerts/explain", json={"id": key})).json()
    assert len(prompts) == 1 and again["read"]["stale"] is False            # saved, not asked again
    d = (await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": key})).json()
    assert d["ai"]["available"] and d["ai"]["read"]["summary"].startswith("procdump")
    await client_cyber.post("/api/v1/threat/alerts/explain", json={"id": key, "fresh": True})
    assert len(prompts) == 2

    async def ai_off(db):
        return None
    monkeypatch.setattr(hunt_ai, "get_ai", ai_off)
    assert (await client_cyber.post("/api/v1/threat/alerts/explain", json={"id": key})).json() == {"available": False}
    assert (await client_cyber.post("/api/v1/threat/alerts/explain", json={"id": "threat_alert_nope:1"})).status_code == 404


@pytest.mark.asyncio
async def test_the_attack_path_opens_in_its_own_page(client_cyber, client_read_only):
    r = await client_cyber.get("/threat/alert/map", params={"id": "threat_alert_x:1"})
    assert r.status_code == 200 and 'id="agp-map"' in r.text and "threat_alert_map.js" in r.text and "attack_map.js" in r.text
    assert (await client_read_only.get("/threat/alert/map", params={"id": "threat_alert_x:1"})).status_code in (302, 303, 403, 404)
