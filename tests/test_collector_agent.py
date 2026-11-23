"""Unit tests for the collector agent's record shaping (no network)."""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))

import collector_common as cc  # noqa: E402
import collector_crowdstrike as cs  # noqa: E402
import collector_cs_policies as csp  # noqa: E402
import collector_ldap as ldapmod  # noqa: E402
import collector_rapid7 as r7  # noqa: E402
import collector_splunk as sp  # noqa: E402


def test_ldap_user_and_computer_shapes():
    u = ldapmod._user({"dn": "CN=J Doe,DC=acme", "attributes": {
        "sAMAccountName": "jdoe", "mail": "jdoe@acme.example", "memberOf": ["CN=IT,DC=acme"], "userAccountControl": 514}}, True)
    assert u["username"] == "jdoe" and u["disabled"] is True and u["groups"] == ["CN=IT,DC=acme"]
    c = ldapmod._computer({"dn": "CN=DESKTOP001,DC=acme", "attributes": {
        "name": "DESKTOP001", "operatingSystem": "Windows 11",
        "lastLogonTimestamp": dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)}}, True)
    assert c["hostname"] == "DESKTOP001" and c["last_logon"].startswith("2026-11-01")


def test_ldap_detects_ad_from_real_ldap3_root_dse():
    # AD used to look like OpenLDAP here and ship zero records
    from types import SimpleNamespace
    from ldap3.protocol.rfc4512 import DsaInfo

    def conn_for(attrs):
        return SimpleNamespace(server=SimpleNamespace(info=DsaInfo(attrs, [])))

    ad = conn_for({"supportedCapabilities": [ldapmod.AD_CAPABILITY],
                   "defaultNamingContext": ["DC=ad,DC=acme,DC=com"]})
    assert ldapmod._flavor(ad) == "ad"
    assert ldapmod._base({}, ad) == "DC=ad,DC=acme,DC=com"
    assert ldapmod._flavor(conn_for({"vendorName": ["OpenLDAP"]})) == "openldap"
    assert ldapmod._flavor(SimpleNamespace(server=SimpleNamespace(info=None))) == "openldap"


def test_ldap_drops_names_the_server_would_reject():
    assert ldapmod._computer({"dn": "x", "attributes": {"name": "bad host!"}}, True) is None
    assert ldapmod._user({"dn": "x", "attributes": {"sAMAccountName": "a\x00b"}}, True) is None


def test_crowdstrike_alert_mapping_and_id_filter():
    a = cs._alert({"composite_id": "cid:ind:abc:1", "severity_name": "High", "device": {"hostname": "server001"},
                   "description": "bad thing"})
    assert a["detection_id"] == "cid:ind:abc:1" and a["behaviors"][0]["description"] == "bad thing"
    assert cs._alert({"composite_id": "has space"}) is None
    assert cs._device({"device_id": "nothex", "hostname": "server001"})["device_id"] is None


def test_rapid7_vuln_keeps_only_real_cves_and_valid_scores():
    v = r7._vuln({"id": "x", "cves": ["CVE-2026-0001", "junk"], "cvss": {"v3": {"score": 11}, "v2": {"score": 5}}})
    assert v["cves"] == ["CVE-2026-0001"] and v["cvss"]["v3"] is None and v["cvss"]["v2"] == {"score": 5.0}
    assert r7._vuln({"cves": []}) is None


def test_splunk_event_sanitizing():
    e = sp._event({"_time": "1", "host": ["a", "b"], "bad key!": "x", "big": "z" * 9000})
    assert "bad key!" not in e and e["host"] == "a b" and len(e["big"]) == 8192


def test_host_port_parsing():
    assert cc.host_port("dc001.acme.example:636") == ("dc001.acme.example", 636)
    assert cc.host_port("console001", 3780) == ("console001", 3780)
    with pytest.raises(ValueError):
        cc.host_port("http://x")


def test_url_json_refuses_plain_http():
    with pytest.raises(ValueError):
        cc.url_json("GET", "http://ctem.acme.example/api")


def test_seal_unseal_and_tamper_checks():
    import collector_crypto as crypto
    priv, pub = crypto.new_identity()
    fp = crypto.fingerprint(pub)
    env = crypto.seal(pub, "p1", "ldap", "password", "s3cret")
    assert crypto.unseal(priv, fp, "p1", "ldap", "password", env) == "s3cret"
    with pytest.raises(crypto.WrongKey):
        crypto.unseal(priv, "0" * 64, "p1", "ldap", "password", env)
    with pytest.raises(Exception):
        crypto.unseal(priv, fp, "p2", "ldap", "password", env)  # moved to another profile


def test_server_and_agent_destination_digests_agree():
    from api.collector.profile import dest_digest
    for kind, s in {"ldap": {"host": "dc001", "port": None, "tls": None, "bind_user": "x"},
                    "splunk": {"host": "s1", "port": 8089, "query": "search x", "username": "u"},
                    "crowdstrike": {"cloud": "us-2", "client_id": "a" * 32},
                    "rapid7_console": {"host": "c1", "port": 3780, "username": "u"}}.items():
        assert dest_digest(kind, s) == cc.dest_digest(kind, s)
    # New destinations count only once set: upgrading doesn't invalidate approvals, setting one asks again
    cs = {"cloud": "us-2", "client_id": "a" * 32}
    assert dest_digest("crowdstrike", {**cs, "fdr": "off", "fdr_queue_url": None}) == dest_digest("crowdstrike", cs)
    q = {**cs, "fdr_queue_url": "https://sqs.us-west-1.amazonaws.com/123456789012/acme-fdr"}
    assert dest_digest("crowdstrike", q) != dest_digest("crowdstrike", cs) and dest_digest("crowdstrike", q) == cc.dest_digest("crowdstrike", q)
    sp = {"host": "s1", "port": 8089, "query": "search x"}
    assert dest_digest("splunk", {**sp, "hec_port": 8088}) == dest_digest("splunk", sp)
    assert dest_digest("splunk", {**sp, "hec_host": "s2", "hec_port": 8088}) == cc.dest_digest("splunk", {**sp, "hec_host": "s2", "hec_port": 8088})


def test_pin_mismatch_raises():
    with pytest.raises(cc.PinMismatch):
        cc.check_pin(b"cert-bytes", "0" * 64)


@pytest.mark.parametrize("kind,s", [
    ("ldap", {"host": "dc001/evil", "tls": "ldaps"}),
    ("ldap", {"host": "dc001", "tls": "plain"}),
    ("splunk", {"host": "s1", "port": 99999, "query": "x"}),
    ("rapid7_console", {"host": "c1:3780", "port": 3780}),
])
def test_box_rejects_bad_destinations(kind, s):
    with pytest.raises(ValueError):
        cc.check_dest(kind, s)


def test_big_batches_split_under_the_body_limit():
    import json

    import ctem_collector as agent
    users = [{"username": f"user{i:05d}", "groups": [f"CN=Group{g},OU=Groups,DC=acme,DC=example" for g in range(40)]}
             for i in range(500)]
    part = {"users": users, "computers": []}
    pieces = list(agent._fit(part, limit=64 * 1024))
    assert len(pieces) > 1
    assert all(len(json.dumps(p, separators=(",", ":"))) <= 64 * 1024 for p in pieces)
    assert [u for p in pieces for u in p["users"]] == users
    small = {"users": users[:2]}
    assert list(agent._fit(small)) == [small]
    assert list(agent._fit({"users": [{"username": "x" * 5000}]}, limit=100)) == [{"users": [{"username": "x" * 5000}]}]


def test_crowdstrike_device_carries_last_user_safely():
    d = cs._device({"device_id": "a" * 32, "hostname": "DESKTOP001", "last_login_user": " jdoe "})
    assert d["last_login_user"] == "jdoe"
    assert cs._device({"hostname": "DESKTOP001", "last_login_user": "j\x1bdoe"})["last_login_user"] is None
    assert cs._device({"hostname": "DESKTOP001", "last_login_user": ["x"]})["last_login_user"] is None


def test_each_source_runs_on_its_own_schedule():
    import ctem_collector as agent
    cfg = {"schedule_minutes": 30}
    ldap = {"kind": "ldap", "settings": {}}
    r7 = {"kind": "rapid7_console", "settings": {"schedule_minutes": 300}}
    splunk = {"kind": "splunk", "settings": {"schedule_minutes": 5}}
    now = 1_000_000.0
    state = {"last_by_kind": {"ldap": now - 31 * 60, "rapid7_console": now - 60 * 60, "splunk": now - 5 * 60}}
    due = [m["kind"] for m in (ldap, r7, splunk) if agent._due(m, cfg, state, now, False)]
    assert due == ["ldap", "splunk"]
    assert agent._due(r7, cfg, state, now, True)  # run-now ignores schedules
    # Upgraded boxes only know the old shared last_run; every source starts from it
    assert [agent._due(m, cfg, {"last_run": now - 10 * 60}, now, False) for m in (ldap, r7, splunk)] == [False, False, True]


def test_crowdstrike_firewall_and_usb_from_policies():
    fw_on, fw_off, usb_block, usb_ro = "a" * 32, "b" * 32, "c" * 32, "d" * 32

    class FakeApi:
        def __init__(self, deny=()):
            self.deny = deny

        def call(self, method, path):
            if any(path.startswith(p) for p in self.deny):
                raise cc.HttpError(403, "forbidden")
            if path.startswith("/policy/entities/firewall/"):
                return {"resources": [{"id": fw_on, "enabled": True}, {"id": fw_off, "enabled": False}]}
            if path.startswith("/fwmgr/entities/policies/"):
                return {"resources": [{"policy_id": fw_on, "enforce": True, "default_inbound": "DENY", "default_outbound": "ALLOW",
                                       "rule_group_ids": ["9" * 32]}, {"policy_id": fw_off, "enforce": False}]}
            if path.startswith("/fwmgr/entities/rule-groups/"):
                return {"resources": [{"id": "9" * 32, "enabled": True, "rule_ids": ["r2", "r1"]}]}
            if path.startswith("/fwmgr/entities/rules/"):
                return {"resources": [
                    {"id": "r1", "name": "Allow RDP from jump hosts", "enabled": True, "action": "ALLOW", "direction": "IN",
                     "protocol": "6", "local_port": [{"start": 3389, "end": 0}], "remote_address": [{"address": "192.0.2.0", "netmask": 24}]},
                    {"id": "r2", "name": "Block SMB", "enabled": True, "action": "DENY", "direction": "IN", "protocol": "6",
                     "local_port": [{"start": 445, "end": 445}], "remote_address": [{"address": "*"}]}]}
            if path.startswith("/policy/entities/prevention/"):
                return {"resources": [{"id": "f" * 32, "name": "Workstations", "enabled": True, "platform_name": "Windows",
                                       "prevention_settings": [{"name": "Exploit Mitigation", "settings": [
                                           {"id": "ForceDEP", "name": "Force DEP", "type": "toggle", "value": {"enabled": True}}]},
                                           {"name": "Machine Learning", "settings": [
                                               {"id": "CloudAntiMalware", "name": "Cloud Anti-malware", "type": "mlslider",
                                                "value": {"detection": "MODERATE", "prevention": "MODERATE"}}]}]}]}
            if path.startswith("/policy/entities/device-control/"):
                mode = {"enforcement_mode": "MONITOR_ENFORCE"}
                return {"resources": [
                    {"id": usb_block, "enabled": True, "settings": {**mode, "classes": [{"id": "MASS_STORAGE", "action": "FULL_BLOCK", "exceptions": [
                        {"vendor_id": "0x0781", "vendor_name": "Acme Storage", "product_id": "5581", "product_name": "Acme Vault",
                         "serial_number": "ACME123", "action": "FULL_ACCESS", "description": "Finance backup drive"}]}]}},
                    {"id": usb_ro, "enabled": True, "settings": {**mode, "classes": [{"id": "MASS_STORAGE", "action": "READ_ONLY"}]}}]}
            raise AssertionError(path)

    def host(fw, usb):
        pol = {"prevention": {"applied": True, "policy_id": "f" * 32}}
        if fw:
            pol["firewall"] = {"applied": True, "policy_id": fw}
        if usb:
            pol["device_control"] = {"applied": True, "policy_id": usb}
        return {"device_id": "e" * 32, "hostname": "DESKTOP001", "device_policies": pol}

    rows = [host(fw_on, usb_block), host(fw_off, usb_ro), host(None, None)]
    p = csp.Policies(FakeApi())
    p.load(rows)
    got = [(cs._device(d, p)["firewall_enabled"], cs._device(d, p)["usb_storage_blocked"]) for d in rows]
    assert got == [(True, True), (False, False), (False, False)]
    every = p.new_policies()
    usb = next(x for x in every if x["kind"] == "device_control" and x["id"] == usb_block)
    assert usb["enforcement"] == "MONITOR_ENFORCE" and usb["classes"][0]["action"] == "FULL_BLOCK"
    assert usb["classes"][0]["allowed"][0] == {"vendor_id": "0781", "vendor": "Acme Storage", "match": None, "product_id": "5581", "product": "Acme Vault",
                                               "serial": "ACME123", "action": "FULL_ACCESS", "description": "Finance backup drive",
                                               "expires": None}
    sent = {x["kind"]: x for x in every if x["id"] in (fw_on, "f" * 32)}
    rs = sent["firewall"]
    assert rs["default_inbound"] == "DENY" and rs["enforce"] and [r["name"] for r in rs["rules"]] == ["Block SMB", "Allow RDP from jump hosts"]
    smb, rdp = rs["rules"]
    assert smb["action"] == "DENY" and smb["protocol"] == "TCP" and smb["local_port"] == [[445, 445]] and smb["remote_address"] == ["*"]
    assert rdp["local_port"] == [[3389, 3389]] and rdp["remote_address"] == ["192.0.2.0/24"]
    assert sent["prevention"]["settings"]["ForceDEP"]["value"] is True
    assert sent["prevention"]["settings"]["CloudAntiMalware"]["value"] == "MODERATE"
    assert sent.get("firewall") and not [x for x in p.new_policies()]   # each policy once per run
    assert cs._device(rows[0], p)["prevention_policy_id"] == "f" * 32 and cs._device(rows[0], p)["firewall_policy_id"] == fw_on
    assert cs._device(rows[0], p)["usb_policy_id"] == usb_block

    denied = csp.Policies(FakeApi(deny=("/policy/entities/device-control/", "/fwmgr/")))
    denied.load(rows)
    first = cs._device(rows[0], denied)
    assert first["firewall_enabled"] is None and first["usb_storage_blocked"] is None  # unknown, not "off"
    assert any("Device control policies: Read" in n for n in denied.notes)                 # CTEM's card says why
    assert any("Firewall management: Read" in n and "HTTP" in n for n in denied.notes)
    assert not p.notes


def test_ad_account_state_from_raw_and_parsed_values():
    now = dt.datetime.now(dt.timezone.utc)

    def ft(d):  # datetime -> AD FILETIME
        return int((d - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)).total_seconds() * 10_000_000)

    u = ldapmod._user({"dn": "CN=J Doe,DC=acme", "attributes": {
        "sAMAccountName": "jdoe", "userAccountControl": 512,
        "lastLogonTimestamp": now - dt.timedelta(days=3), "pwdLastSet": ft(now - dt.timedelta(days=400)),
        "msDS-UserPasswordExpiryTimeComputed": ft(now - dt.timedelta(days=10)),
        "msDS-User-Account-Control-Computed": 0x10}}, True)
    assert u["pwd_expired"] is True and u["locked_out"] is True and u["pwd_never_expires"] is False
    assert u["last_logon"].startswith(str((now - dt.timedelta(days=3)).date()))
    assert u["pwd_last_set"].startswith(str((now - dt.timedelta(days=400)).date()))

    svc = ldapmod._user({"dn": "CN=svc,DC=acme", "attributes": {
        "sAMAccountName": "svc-backup", "userAccountControl": 0x10000 | 0x2, "pwdLastSet": 0,
        "msDS-UserPasswordExpiryTimeComputed": 0x7FFFFFFFFFFFFFFF,
        "lastLogonTimestamp": dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)}}, True)
    assert svc["disabled"] and svc["pwd_never_expires"] and not svc["pwd_expired"]
    assert svc["pwd_last_set"] is None and svc["last_logon"] is None and svc["pwd_expires"] is None


def test_rapid7_console_tag_map(monkeypatch):
    calls = {"/api/3/tags": {"resources": [{"id": 1, "name": "Dallas", "type": "location"},
                                           {"id": 2, "name": "High", "type": "criticality"},
                                           {"id": "x", "name": "bad id"}], "page": {"totalPages": 1}},
             "/api/3/tags/1/assets": {"resources": [10, 11]}, "/api/3/tags/2/assets": {"resources": [10]}}
    monkeypatch.setattr(r7, "_get", lambda s, secret, path: calls[path.split("?")[0]])
    tags = r7._tag_map({}, {})
    assert tags == {10: [{"type": "location", "name": "Dallas"}, {"type": "criticality", "name": "High"}],
                    11: [{"type": "location", "name": "Dallas"}]}
    assert r7._asset({"id": 11, "hostName": "server001"}, tags)["tags"] == [{"type": "location", "name": "Dallas"}]
    assert "tags" not in r7._asset({"id": 11, "hostName": "server001"}, None)  # couldn't read: send nothing

    def denied(s, secret, path):
        raise cc.HttpError(403)
    monkeypatch.setattr(r7, "_get", denied)
    assert r7._tag_map({}, {}) is None


def test_rapid7_pages_shrink_on_timeout_without_losing_rows(monkeypatch):
    rows = list(range(450))
    seen_sizes = []

    def fake_get(s, secret, path):
        size = int(path.split("size=")[1].split("&")[0])
        page = int(path.split("page=")[1])
        seen_sizes.append(size)
        if size == 200 and page == 1:
            raise TimeoutError("The read operation timed out")
        chunk = rows[page * size:(page + 1) * size]
        return {"resources": chunk, "page": {"totalResources": len(rows), "totalPages": -(-len(rows) // size)}}

    monkeypatch.setattr(r7, "_get", fake_get)
    got = [x for page in r7._pages({}, {}, "/api/3/assets") for x in page]
    assert got == rows  # every row exactly once, in order
    assert seen_sizes[:3] == [200, 200, 100]

    monkeypatch.setattr(r7, "_get", lambda s, secret, path: (_ for _ in ()).throw(TimeoutError()))
    with pytest.raises(RuntimeError, match="took over"):
        list(r7._pages({}, {}, "/api/3/assets"))


def test_ldap_user_profile_fields():
    u = ldapmod._user({"dn": "CN=J Doe,DC=acme", "attributes": {
        "sAMAccountName": "jdoe", "userAccountControl": 512, "givenName": "Jane", "sn": "Doe",
        "title": "Security Analyst", "telephoneNumber": "(201) 555-0123", "mobile": "bad\nvalue", "c": "US"}}, True)
    assert (u["first_name"], u["last_name"], u["title"], u["phone"], u["country"]) == \
        ("Jane", "Doe", "Security Analyst", "(201) 555-0123", "US")
    assert u["mobile"] is None


def test_ldap_user_upn():
    u = ldapmod._user({"dn": "CN=J Doe,DC=acme", "attributes": {
        "sAMAccountName": "jdoe", "userAccountControl": 512, "userPrincipalName": "jane.doe@ad.acme.example"}}, True)
    assert u["upn"] == "jane.doe@ad.acme.example"
    bad = ldapmod._user({"dn": "", "attributes": {"sAMAccountName": "x", "userPrincipalName": "no at sign"}}, True)
    assert bad["upn"] is None


def test_crowdstrike_login_history_newest_real_names_first():
    did = "f" * 32

    class FakeApi:
        def __init__(self, status=None):
            self.status, self.paths = status, []

        def call(self, method, path, body=None):
            self.paths.append(path)
            if self.status and (self.status != 404 or path.endswith("/v2")):
                raise cc.HttpError(self.status, "nope")
            assert method == "POST" and body == {"ids": [did]}
            return {"resources": [{"device_id": did, "recent_logins": [
                {"user_name": "SpecopsClient_150209", "login_time": "2026-11-20T10:00:00Z"},
                {"user_name": "ACME\\jdoe", "login_time": "2026-11-19T08:00:00Z"},
                {"user_name": "acme\\JDOE", "login_time": "2026-11-18T08:00:00Z"},
                {"user_name": "bad\nname", "login_time": "2026-11-20T11:00:00Z"}]}]}

    rows = [{"device_id": did, "hostname": "DESKTOP001"}, {"device_id": "nothex"}]
    logins = cs._Logins(FakeApi()).load(rows)
    assert logins == {did: ["SpecopsClient_150209", "ACME\\jdoe"]}
    assert cs._device(rows[0], None, logins)["recent_logins"] == ["SpecopsClient_150209", "ACME\\jdoe"]
    assert cs._device(rows[0])["recent_logins"] is None

    old = FakeApi(status=404)  # v2 missing falls back to v1
    assert cs._Logins(old).load(rows) == logins and old.paths[-1].endswith("/v1")
    denied = cs._Logins(FakeApi(status=403))
    assert denied.load(rows) == {} and denied.off


def test_crowdstrike_alert_details_and_recent_window():
    a = cs._alert({"composite_id": "cid:ind:abc:2", "severity_name": "Critical", "display_name": "Credential theft",
                   "status": "in_progress", "created_timestamp": "2026-11-20T10:00:00Z", "tactic_id": "TA0006",
                   "technique_id": "T1003.001", "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/x",
                   "device": {"hostname": "desktop001", "device_id": "a" * 32}})
    assert (a["title"], a["status"], a["detected_at"], a["tactic_id"], a["technique_id"]) == \
        ("Credential theft", "in_progress", "2026-11-20T10:00:00Z", "TA0006", "T1003.001")
    assert a["link"].startswith("https://falcon.crowdstrike.com/") and a["device"]["device_id"] == "a" * 32
    bad = cs._alert({"composite_id": "cid:2", "technique_id": "T1<x>", "falcon_host_link": "https://evil.example/x",
                     "device": {"device_id": "nothex"}, "display_name": "a\nb"})
    assert bad["technique_id"] is None and bad["link"] is None and bad["device"]["device_id"] is None and bad["title"] == "a b"  # control characters become spaces
    q = cs._alert_query(1000, dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc))
    assert "offset=1000" in q and "created_timestamp%3A%3E%272026-10-21T00%3A00%3A00Z%27" in q and "status" not in q


def test_rapid7_console_software_reads_each_asset_and_groups(monkeypatch):
    chrome = {"id": 1, "vendor": "Google LLC", "product": "Chrome", "family": "Chrome", "version": "120.0",
              "type": "Web Browser", "cpe": {"v2.3": "cpe:2.3:a:google:chrome:120.0"}}
    ff = {"id": 2, "vendor": "Mozilla", "product": "Firefox", "version": "128.0"}
    calls = []

    def get(s, secret, path):
        calls.append(path)
        if path == "/api/3/assets/12/software":
            raise cc.HttpError(404, "gone")
        return {"/api/3/assets/10/software": {"resources": [chrome, ff, "junk"]},
                "/api/3/assets/11/software": {"resources": [chrome]}}[path]
    monkeypatch.setattr(r7, "_get", get)
    out = [b for b in r7._software({}, "x", {10: "ws-01", 11: "srv-02", 12: "old-03"})]
    assert calls == ["/api/3/assets/10/software", "/api/3/assets/11/software", "/api/3/assets/12/software"]
    items = {i["product"]: i for b in out for i in b}
    assert items["Chrome"]["hosts"] == ["ws-01", "srv-02"] and items["Chrome"]["cpe"].startswith("cpe:2.3:a:google")
    assert items["Chrome"]["version"] == "120.0" and items["Chrome"]["family"] == "Chrome"
    assert items["Firefox"]["hosts"] == ["ws-01"] and len(items) == 2   # a gone asset is skipped, not a failed run

    monkeypatch.setattr(r7, "CHUNK_ASSETS", 1)
    monkeypatch.setattr(r7, "_get", lambda s, secret, path: {"resources": [chrome]})
    assert len(list(r7._software({}, "x", {1: "a", 2: "b"}))) == 2       # sent every chunk of assets

    def denied(s, secret, path):
        raise cc.HttpError(403, "no")
    monkeypatch.setattr(r7, "_get", denied)
    out = list(r7._software({}, "x", {1: "a"}))                          # no access: skipped, never a failed run
    assert len(out) == 1 and "can't read asset software" in out[0]      # ...but CTEM hears about it
    monkeypatch.setattr(r7, "_get", lambda s, secret, path: {"resources": []})
    out = list(r7._software({}, "x", {1: "a", 2: "b"}))
    assert out == ["the console returned no software for any of 2 assets"]



def test_rapid7_software_counts_as_done_only_when_sent(monkeypatch):
    calls = []

    def fake(s, secret, names):
        calls.append(1)
        yield from feed
    monkeypatch.setattr(r7, "_software", fake)
    s, state = {"host": "console001"}, {}
    feed = ["the console returned no software for any of 1 assets"]
    assert list(r7._software_due(s, "x", state, {1: "a"})) == [{"warnings": feed}]
    assert "rapid7_software_sent_at:console001" not in state                 # nothing sent: not done...
    assert list(r7._software_due(s, "x", state, {1: "a"})) == [] and len(calls) == 1   # ...but not retried at once
    state["rapid7_software_tried_at:console001"] -= r7.RETRY_HOURS * 3600 + 1
    feed = [[{"product": "Chrome", "hosts": ["a"]}]]
    assert list(r7._software_due(s, "x", state, {1: "a"})) == [{"software": feed[0]}]
    assert "rapid7_software_sent_at:console001" in state and len(calls) == 2
    state["rapid7_software_tried_at:console001"] = 0
    assert list(r7._software_due(s, "x", state, {1: "a"})) == [] and len(calls) == 2   # sent today: done
    assert list(r7._software_due({"host": "c2", "software_hours": 0}, "x", {}, {1: "a"})) == []   # 0 = off



def test_device_control_v2_layout_and_watch_counts():
    v2 = {"id": "a" * 32, "enabled": True, "usb_settings": {"enforcement_mode": "MONITOR_ENFORCE", "classes": [
        {"id": "x1", "class": "MASS_STORAGE", "action": "WHITELIST", "exceptions": [
            {"id": "e1", "action": "FULL_ACCESS", "class": "MASS_STORAGE", "match_method": "VID_PID_SERIAL",
             "vendor_id": "0781", "vendor_name": "Acme Storage", "serial_number": "ACME9"}]}]}}
    p = csp.Policies(None)
    p.usb = {"a" * 32: v2, "b" * 32: {"id": "b" * 32, "enabled": True, "settings": {"enforcement_mode": "MONITOR_ENFORCE", "classes": [
        {"id": "MASS_STORAGE", "action": "READ_ONLY"}]}}, "c" * 32: {"id": "c" * 32, "enabled": True, "settings": {
            "enforcement_mode": "MONITOR_ENFORCE", "classes": [{"id": "IMAGING", "action": "FULL_BLOCK"}]}}}
    host = lambda pid: {"device_policies": {"device_control": {"applied": True, "policy_id": pid}}}  # noqa: E731
    assert p.usb_blocked(host("a" * 32)) is True            # allow-list only: blocked except what's allowed
    assert p.usb_blocked(host("b" * 32)) is False           # read-only isn't blocked
    assert p.usb_blocked(host("c" * 32)) is None            # says nothing about USB storage: unknown, not "off"
    s = csp.usb_summary("a" * 32, v2)
    assert s["classes"][0]["id"] == "MASS_STORAGE" and s["classes"][0]["allowed"][0]["match"] == "VID_PID_SERIAL"
    assert csp.rule_summary({"monitor": {"count": "0", "period_ms": "0"}})["logged"] is False
    assert csp.rule_summary({"monitor": {"count": "5", "period_ms": "60000"}})["logged"] is True
    r = csp.rule_summary({"fqdn_enabled": True, "fqdn": "*.badsite.example;badsite.example; bad name",
                          "fields": [{"name": "image_name", "value": "C:\\Program Files\\Acme\\tunnel.exe"}]})
    assert r["fqdn"] == ["*.badsite.example", "badsite.example", "bad", "name"] and r["program"].endswith("tunnel.exe")
    assert csp.rule_summary({"fqdn_enabled": False, "fqdn": "badsite.example"})["fqdn"] == []

