"""Unit tests for the collector agent's record shaping (no network)."""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))

import collector_common as cc  # noqa: E402
import collector_crowdstrike as cs  # noqa: E402
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
                return {"resources": [{"policy_id": fw_on, "enforce": True}, {"policy_id": fw_off, "enforce": False}]}
            if path.startswith("/policy/entities/device-control/"):
                mode = {"enforcement_mode": "MONITOR_ENFORCE"}
                return {"resources": [
                    {"id": usb_block, "enabled": True, "settings": {**mode, "classes": [{"id": "MASS_STORAGE", "action": "BLOCK_ALL"}]}},
                    {"id": usb_ro, "enabled": True, "settings": {**mode, "classes": [{"id": "MASS_STORAGE", "action": "READ_ONLY"}]}}]}
            raise AssertionError(path)

    def host(fw, usb):
        pol = {}
        if fw:
            pol["firewall"] = {"applied": True, "policy_id": fw}
        if usb:
            pol["device_control"] = {"applied": True, "policy_id": usb}
        return {"device_id": "e" * 32, "hostname": "DESKTOP001", "device_policies": pol}

    rows = [host(fw_on, usb_block), host(fw_off, usb_ro), host(None, None)]
    p = cs._Policies(FakeApi())
    p.load(rows)
    got = [(cs._device(d, p)["firewall_enabled"], cs._device(d, p)["usb_storage_blocked"]) for d in rows]
    assert got == [(True, True), (False, False), (False, False)]

    denied = cs._Policies(FakeApi(deny=("/policy/entities/device-control/", "/fwmgr/")))
    denied.load(rows)
    first = cs._device(rows[0], denied)
    assert first["firewall_enabled"] is None and first["usb_storage_blocked"] is None  # unknown, not "off"


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
