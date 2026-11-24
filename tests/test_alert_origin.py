"""Logon and identity alerts: where the attempts came from and which accounts they targeted are kept, shown on the
alert and its map, and put into Threat Curated Rule findings; alerts saved without detail are fetched again."""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from tests.test_threat_detail import RAW

LOGONS = {**RAW, "display_name": "SuspiciousFailedLogons", "description": "A highly suspicious sequence of failed remote logons.",
          "tactic": "Credential Access", "technique": "Brute Force", "technique_id": "T1110",
          "source_endpoint_ip_address": "10.20.30.40", "source_endpoint_host_name": "WS-ATTACKER",
          "target_account_name": "administrator", "logon_type": "Network", "failed_logons": [5, 7],
          "sha256": "f" * 64, "agent_id": "a" * 32}


def test_the_parser_keeps_where_and_who_but_not_hashes_or_ids():
    from api.core.cs_alert import csa
    d = csa.clean(csa.summary(LOGONS)["detail"])
    ctx = dict(d["context"])
    assert ctx["source_endpoint_ip_address"] == "10.20.30.40" and ctx["source_endpoint_host_name"] == "WS-ATTACKER"
    assert ctx["target_account_name"] == "administrator" and ctx["failed_logons"] == "5, 7"
    assert not any(k in ctx for k in ("sha256", "agent_id", "cmdline", "filepath"))
    hostile = csa.clean({"context": [["ok_ip", "192.0.2.44"], ["BAD KEY <x>", "v"], ["ctl", "a\x00b"], "junk", ["x", {"a": 1}]]})
    assert hostile["context"] == [["ok_ip", "192.0.2.44"], ["ctl", "a b"]]


def test_the_map_shows_where_it_came_from_and_what_it_targeted():
    from api.core.cs_alert import csa
    from api.core.threat_graph import build, origin
    d = csa.clean(csa.summary(LOGONS)["detail"])
    assert origin(d) == {"ips": ["10.20.30.40"], "hosts": ["WS-ATTACKER"], "accounts": [], "targets": ["administrator"]}
    g = build({"hostname": "SSDC06", "title": "SuspiciousFailedLogons"}, d)
    kinds = {n["label"]: n for n in g["nodes"]}
    assert kinds["10.20.30.40"]["kind"] == "ip" and kinds["WS-ATTACKER"]["kind"] == "host" and kinds["administrator"]["kind"] == "user"
    edges = {(e["from"], e["to"], e["label"]) for e in g["edges"]}
    assert ("from0", "host", "from") in edges and ("host", "tgt0", "targeted") in edges
    pos = {n["id"]: n["x"] for n in g["nodes"]}
    assert all(pos[e["to"]] > pos[e["from"]] for e in g["edges"])


@pytest.mark.asyncio
async def test_a_curated_finding_names_the_source_and_the_accounts(db):
    from api.core.cs_alert import csa
    from api.hunt import curated
    from api.integrations.base import get_connector
    from api.models.threat_rule import ThreatRule
    tag = uuid.uuid4().hex[:8]
    s = csa.summary({**LOGONS, "composite_id": f"cid:ind:{tag}:1", "display_name": f"SuspiciousFailedLogons{tag}",
                     "created_timestamp": None, "timestamp": None})
    await get_connector("crowdstrike", {"client_id": "x", "client_secret": "y"})._cache_threats([s], db)
    m = curated.validate("alert", {"title_any": [f"SuspiciousFailedLogons{tag}"]})
    rule = ThreatRule(name=f"Failed logons {tag}", kind="alert", match=m, fingerprint=curated.fingerprint("alert", m), severity="high",
                      status="manual", enabled=True)
    db.add(rule)
    await db.commit()
    try:
        issues, lookups, _ = await curated.run(db, None, "all", 1)
        mine = next(i for i in issues if i["title"] == rule.name)
        assert mine["involved"]["ips"] == ["10.20.30.40"] and "WS-ATTACKER" in mine["involved"]["hosts"]
        assert "administrator" in mine["involved"]["users"] and "ACME\\jdoe" in mine["involved"]["users"]
        assert "from 10.20.30.40" in mine["timeline"][0]["what"] and "against administrator" in mine["timeline"][0]["what"]
        lk = lookups[mine["lookups"][0] - 1]
        row = lk["rows"][0]
        assert row["from"] == "10.20.30.40, WS-ATTACKER" and row["targeted"] == "administrator"
        assert row["alert_page"].startswith("/threat/alert?id=threat_alert_cid%3Aind%3A")
    finally:
        await db.delete(rule)
        await db.commit()


@pytest.mark.asyncio
async def test_alerts_without_detail_are_asked_for_again_once_a_week(db, client, client_admin):
    from api.core import cs_alert_refresh
    from api.models.settings import AppSetting
    from tests.test_collector import _KEY, _auth, _code_from, _profile
    tag = uuid.uuid4().hex[:8]
    bare, full = f"threat_alert_{tag}:ind:{tag}:1", f"threat_alert_{tag}:ind:{tag}:2"
    db.add_all([AppSetting(key=bare, is_sensitive=False, value=json.dumps({"source": "crowdstrike", "description": "old"})),
                AppSetting(key=full, is_sensitive=False, value=json.dumps({"source": "crowdstrike", "detail_enc": "x"})),
                AppSetting(key=f"threat_alert_s1_{tag}", is_sensitive=False, value=json.dumps({"source": "sentinelone"}))])
    await db.commit()
    first = await cs_alert_refresh.due(db, limit=100000)
    await db.commit()
    assert f"{tag}:ind:{tag}:1" in first and f"{tag}:ind:{tag}:2" not in first and not any(f"s1_{tag}" in x for x in first)
    assert f"{tag}:ind:{tag}:1" not in await cs_alert_refresh.due(db, limit=100000)   # not again within the week
    p = await _profile(client_admin, {"crowdstrike": {"settings": {"client_id": "a" * 32}}})
    code = _code_from((await client_admin.post(f"/api/v1/collectors/{p['id']}/installer", json={"allowed_cidrs": []})).text)
    tok = (await client.post("/api/v1/collector/enroll", json={"code": code, "hostname": "server001", "agent_version": "1.8.1",
                                                                "public_key": _KEY[1]})).json()["token"]
    iid = (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()["modules"]["crowdstrike"]["integration_id"]
    r = await client.get(f"/api/v1/collector/alert-refresh/{iid}", headers=_auth(tok))
    assert r.status_code == 200 and isinstance(r.json()["ids"], list)
    assert (await client.get(f"/api/v1/collector/alert-refresh/{uuid.uuid4()}", headers=_auth(tok))).status_code == 404
    assert (await client.get(f"/api/v1/collector/alert-refresh/{iid}")).status_code in (401, 403)


def test_the_tamper_alert_keeps_what_the_falcon_console_shows():
    """The fields an analyst reads in the Falcon console for an EDR tampering alert are in CTEM too."""
    from api.core.cs_alert import csa
    from api.core.threat_graph import build
    a = {**RAW, "composite_id": "cid:ind:tamper:1", "display_name": "FileSystemTamperFalconSensorDynamicConfiguration",
         "name": "FileSystemTamperFalconSensorDynamicConfiguration", "filename": "dllhost.exe",
         "filepath": "\\Device\\HarddiskVolume3\\Windows\\System32\\dllhost.exe",
         "cmdline": "C:\\windows\\system32\\DllHost.exe /Processid:{4D111E08-CBF7-4F12-A926-2C7920AF52FC}",
         "sha256": "b" * 64, "sha1": "f" * 40, "user_name": "admw11270", "user_id": "S-1-5-21-1-116646", "logon_domain": "ACME",
         "local_admin": True, "logon_type": "CACHED_INTERACTIVE", "login_server": "DC05", "login_time": "2026-11-20T16:01:16Z",
         "files_accessed": [{"filepath": "\\Device\\HarddiskVolume3\\Program Files\\CrowdStrike\\Database",
                             "timestamp": "2026-10-13T10:39:42Z"}],
         "pattern_disposition_details": {"fs_operation_blocked": True}, "global_prevalence": "common", "local_prevalence": "common"}
    d = csa.clean(csa.summary(a)["detail"])
    assert d["process"]["cmdline"].endswith("{4D111E08-CBF7-4F12-A926-2C7920AF52FC}") and d["process"]["sha1"] == "f" * 40
    assert d["files_accessed"][0]["filepath"].endswith("CrowdStrike\\Database") and d["disposition"]["actions"] == ["fs_operation_blocked"]
    assert d["user"]["sid"] == "S-1-5-21-1-116646" and d["prevalence"] == {"global": "common", "local": "common"}
    ctx = dict(d["context"])
    assert ctx["local_admin"] == "yes" and ctx["logon_type"] == "CACHED_INTERACTIVE" and ctx["login_server"] == "DC05"
    assert ctx["login_time"] == "2026-11-20T16:01:16Z"
    g = build({"hostname": "L-1", "title": "FileSystemTamperFalconSensorDynamicConfiguration", "technique": "Disable or Modify Tools"}, d)
    went = [n for n in g["nodes"] if n["label"] == "Database"]
    assert went and any(e["label"] == "Went after" for e in g["edges"])
    proc = next(n for n in g["nodes"] if n["id"] == "process")
    assert ["SHA1", "f" * 40] in proc["facts"] and any(k == "MITRE" for k, _ in proc["facts"])


@pytest.mark.asyncio
async def test_hunt_evidence_names_the_process_file_and_crowdstrike_link(db):
    """'A remote process obtained a handle to lsass' says which process, which file, and links to Falcon."""
    from api.core.cs_alert import csa
    from api.hunt import alert_detail, curated
    from api.integrations.base import get_connector
    from api.models.threat_rule import ThreatRule
    tag = uuid.uuid4().hex[:8]
    raw = {**RAW, "composite_id": f"cid:ind:{tag}:1", "display_name": f"LsassHandle{tag}", "created_timestamp": None, "timestamp": None,
           "filename": "evil.exe", "filepath": "\\Device\\HarddiskVolume3\\Users\\Public\\evil.exe", "cmdline": "evil.exe -dump",
           "ioc_type": "filename", "ioc_value": "C:\\Windows\\Temp\\untrusted.dll",
           "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/x?_cid=abc"}
    await get_connector("crowdstrike", {"client_id": "x", "client_secret": "y"})._cache_threats([csa.summary(raw)], db)
    key = f"threat_alert_cid:ind:{tag}:1"
    lookups = [{"columns": ["source", "description", "alert_key"], "rows": [{"source": "crowdstrike", "description": "x", "alert_key": key}]}]
    await alert_detail.enrich(db, lookups)
    row, cols = lookups[0]["rows"][0], lookups[0]["columns"]
    assert row["process"].endswith("evil.exe") and row["command_line"] == "evil.exe -dump" and row["parent"] == "powershell.exe"
    assert row["file"] == "C:\\Windows\\Temp\\untrusted.dll" and row["crowdstrike"].startswith("https://falcon.crowdstrike.com/")
    assert cols[-1] == "alert_key" and "process" in cols and "crowdstrike" in cols
    m = curated.validate("alert", {"title_any": [f"LsassHandle{tag}"]})
    rule = ThreatRule(name=f"Lsass {tag}", kind="alert", match=m, fingerprint=curated.fingerprint("alert", m), severity="high",
                      status="manual", enabled=True)
    db.add(rule)
    await db.commit()
    try:
        issues, lks, _ = await curated.run(db, None, "all", 1)
        mine = next(i for i in issues if i["title"] == rule.name)
        assert "by evil.exe (started by powershell.exe)" in mine["timeline"][0]["what"]
        assert "on C:\\Windows\\Temp\\untrusted.dll" in mine["timeline"][0]["what"]
        r = lks[mine["lookups"][0] - 1]["rows"][0]
        assert r["crowdstrike"].startswith("https://falcon.crowdstrike.com/") and r["command_line"] == "evil.exe -dump"
    finally:
        await db.delete(rule)
        await db.commit()


def test_an_ai_story_step_names_the_process_and_file_of_its_alert():
    from api.hunt.alert_detail import annotate
    lookups = [{"rows": [{"hostname": "WS-1", "description": "Signed DLL with untrusted root authority loaded by LSASS process",
                          "process": "C:/Windows/System32/lsass.exe", "file": "C:\\Temp\\odd.dll"},
                         {"hostname": "WS-2", "description": "Something else entirely", "process": "x.exe"}]}]
    issues = [{"involved": {"hosts": ["WS-1"]}, "timeline": [
        {"what": "A signed DLL with an untrusted root authority was loaded by LSASS.", "lookup": 1},
        {"what": "Unrelated step", "lookup": 1}, {"what": "No evidence", "lookup": 9}]}]
    annotate(issues, lookups)
    steps = issues[0]["timeline"]
    assert steps[0]["what"].endswith("Process: lsass.exe; File: C:\\Temp\\odd.dll.")
    assert steps[1]["what"] == "Unrelated step" and steps[2]["what"] == "No evidence"
