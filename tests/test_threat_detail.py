"""CrowdStrike alert detail: parsed once (shipper and CTEM), encrypted at rest, told as a story and a timeline."""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

HOST = "DESKTOP001"
RAW = {
    "composite_id": "cid:ind:aaaa:1", "aggregate_id": "aggind:aaaa:42", "display_name": "CredentialDumping",
    "description": "A process tried to read LSASS memory.", "severity": 90, "severity_name": "Critical",
    "confidence": 80, "objective": "Gain Access", "scenario": "credential_theft", "status": "new",
    "tactic": "Credential Access", "tactic_id": "TA0006", "technique": "OS Credential Dumping", "technique_id": "T1003.001",
    "timestamp": "2026-11-20T10:00:05Z", "created_timestamp": "2026-11-20T10:00:09Z", "updated_timestamp": "2026-11-20T11:30:00Z",
    "assigned_to_name": "Jane Doe", "user_name": "jdoe", "logon_domain": "ACME", "user_principal": "jdoe@acme.example",
    "filename": "procdump.exe", "filepath": "\\Device\\HarddiskVolume3\\Users\\jdoe\\procdump.exe",
    "cmdline": "procdump.exe -ma lsass.exe out.dmp", "sha256": "a" * 64, "md5": "b" * 32, "process_start_time": 1795168800,
    "parent_details": {"filename": "powershell.exe", "cmdline": "powershell -enc AAAA", "sha256": "c" * 64,
                       "timestamp": "2026-11-20T09:59:58Z", "user_name": "jdoe"},
    "grandparent_details": {"filename": "explorer.exe", "timestamp": "2026-11-20T08:00:00Z"},
    "pattern_disposition_description": "Prevention, process killed.",
    "pattern_disposition_details": {"kill_process": True, "quarantine_file": True, "detect": True, "evil": True},
    "quarantined_files": [{"filename": "procdump.exe", "sha256": "a" * 64, "state": "quarantined"}],
    "network_accesses": [{"remote_address": "203.0.113.7", "remote_port": 443, "local_address": "192.0.2.10",
                          "local_port": 50123, "protocol": "TCP", "connection_direction": "0",
                          "access_timestamp": 1795168803}],
    "dns_requests": [{"domain_name": "files.acme-bad.example", "request_type": "A", "load_timestamp": "2026-11-20T10:00:02Z"}],
    "device": {"device_id": "d" * 32, "hostname": HOST, "platform_name": "Windows", "os_version": "Windows 11",
               "local_ip": "192.0.2.10", "external_ip": "198.51.100.4", "status": "normal", "ou": ["Workstations"]},
    "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/x",
}


def test_parser_keeps_the_story_and_drops_anything_unexpected():
    from api.core.cs_alert import csa
    s = csa.summary(RAW)
    d = s["detail"]
    assert d["process"]["cmdline"].startswith("procdump.exe -ma") and d["parent"]["filename"] == "powershell.exe"
    assert d["grandparent"]["filename"] == "explorer.exe" and d["user"]["principal"] == "jdoe@acme.example"
    assert d["disposition"]["actions"] == ["kill_process", "quarantine_file", "detect"]   # "evil" isn't a known flag
    assert d["network"][0] == {"direction": "outbound", "protocol": "TCP", "local": "192.0.2.10", "local_port": 50123,
                               "remote": "203.0.113.7", "remote_port": 443, "at": "2026-11-20T10:00:03+00:00"}
    assert d["dns"][0]["domain"] == "files.acme-bad.example" and d["host"]["external_ip"] == "198.51.100.4"
    # The CTEM side rebuilds from known keys: injected keys, bad hashes and control characters don't survive
    hostile = {**d, "x_injected": "<script>", "process": {**d["process"], "sha256": "zz", "cmdline": "a\x00b\nc"},
               "network": [{"remote": "not an ip!", "at": "yesterday"}], "disposition": {"actions": ["rm_rf", "kill_process"]}}
    c = csa.clean(hostile)
    assert "x_injected" not in c and "sha256" not in c["process"] and c["process"]["cmdline"] == "a b c"
    assert "network" not in c and c["disposition"]["actions"] == ["kill_process"]
    assert csa.clean("nope") == {} and csa.when("2026-02-30T00:00:00Z") is None and csa.when(5) is None


@pytest.mark.asyncio
async def test_detail_is_encrypted_and_the_page_gets_story_timeline_related(db, client_cyber, client_read_only):
    from api.core.cs_alert import csa
    from api.integrations.base import get_connector
    from api.models.settings import AppSetting
    tag = uuid.uuid4().hex[:8]
    main = csa.summary({**RAW, "composite_id": f"cid:ind:{tag}:1"})
    other = csa.summary({**RAW, "composite_id": f"cid:ind:{tag}:2", "display_name": "Suspicious PowerShell",
                         "created_timestamp": "2026-11-20T09:59:59Z", "aggregate_id": f"aggind:{tag}"})
    conn = get_connector("crowdstrike", {"client_id": "x", "client_secret": "y"})
    await conn._cache_threats([main, other], db)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == f"threat_alert_cid:ind:{tag}:1"))).scalar_one()
    assert "procdump" not in row.value and "jdoe" not in row.value and json.loads(row.value)["detail_enc"]

    listed = (await client_cyber.get("/api/v1/threat/alerts", params={"q": tag})).json()
    assert listed["total"] == 2 and "detail_enc" not in json.dumps(listed) and "procdump" not in json.dumps(listed)
    url = "/api/v1/threat/alerts/detail"
    assert (await client_read_only.get(url, params={"id": f"threat_alert_cid:ind:{tag}:1"})).status_code == 403
    a = (await client_cyber.get(url, params={"id": f"threat_alert_cid:ind:{tag}:1"})).json()
    assert a["has_detail"] and a["detail"]["process"]["filename"] == "procdump.exe"
    assert "procdump.exe ran on" in a["story"] and "killed the process" in a["story"] and "as jdoe" in a["story"]
    assert a["actions_text"] == ["killed the process", "quarantined the file"]
    kinds = [e["kind"] for e in a["timeline"]]
    assert kinds[0] == "process" and {"dns", "network", "detection", "action", "related", "status"} <= set(kinds)
    assert [e["at"] for e in a["timeline"]] == sorted(e["at"] for e in a["timeline"])
    assert [r["title"] for r in a["related"]] == ["Suspicious PowerShell"]
