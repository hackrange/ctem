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
