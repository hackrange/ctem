"""Shipper set-url: move to CTEM's new address without re-enrolling, only when it's the same CTEM."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))

import collector_common as cc  # noqa: E402
import collector_core as core  # noqa: E402
import collector_setup as setup  # noqa: E402

OLD, NEW = "https://ctem-old.acme.example", "https://ctem.acme.example"


@pytest.fixture
def box(tmp_path, monkeypatch):
    (tmp_path / "collector.json").write_text(json.dumps(
        {"ctem_url": OLD, "ctem_ca_file": None, "name": "box1", "profile_id": "prof-1", "collector_id": "c-1"}))
    (tmp_path / "identity.json").write_text(json.dumps({"token": "tok-1", "private_key": "x", "public_key": "y"}))
    (tmp_path / "pins.json").write_text(json.dumps({"ldap": {"digest": "d1", "dest": "ldaps://dc.acme.example"}}))
    monkeypatch.setattr(core, "test_ctem", lambda url, cafile=None, quiet=False: {"service": "open-ctem"})
    monkeypatch.setattr(cc, "say", lambda *a, **k: None)
    seen = {}

    def fake_call(self, method, path, body=None, retries=0):
        seen.update(url=self.url, token=self.token, path=path, body=body)
        return seen.get("answer", {"profile_id": "prof-1"})
    monkeypatch.setattr(core.Ctem, "call", fake_call)
    return tmp_path, seen


def _args(url=NEW, ca_file=None):
    return SimpleNamespace(url=url, ca_file=ca_file, yes=True)


def _url(path):
    return json.loads((path / "collector.json").read_text())["ctem_url"]


def test_switches_when_the_new_address_is_the_same_ctem(box):
    path, seen = box
    assert setup.set_url(_args(), str(path)) == 0
    assert _url(path) == NEW
    assert seen["url"] == NEW and seen["token"] == "tok-1" and seen["path"] == "/api/v1/collector/checkin"
    assert seen["body"]["approved"] == {"ldap": "d1"}   # approvals carried over, nothing re-approved
    conf = json.loads((path / "collector.json").read_text())
    assert conf["profile_id"] == "prof-1" and conf["collector_id"] == "c-1"


def test_refuses_a_different_ctem(box, monkeypatch):
    path, seen = box

    def reject(self, *a, **k):
        raise cc.HttpError(401, "nope")
    monkeypatch.setattr(core.Ctem, "call", reject)
    with pytest.raises(SystemExit, match="different CTEM install"):
        setup.set_url(_args(), str(path))
    assert _url(path) == OLD


def test_refuses_a_different_profile_and_bad_urls(box, monkeypatch):
    path, seen = box
    seen["answer"] = {"profile_id": "someone-else"}
    with pytest.raises(SystemExit, match="different shipper profile"):
        setup.set_url(_args(), str(path))
    for bad in ("http://ctem.acme.example", "https://ctem.acme.example/path", "ctem.acme.example"):
        with pytest.raises(SystemExit):
            setup.set_url(_args(bad), str(path))
    with pytest.raises(SystemExit, match="CA bundle not found"):
        setup.set_url(_args(ca_file="/nope/ca.pem"), str(path))
    assert _url(path) == OLD


def test_unreachable_new_address_changes_nothing(box, monkeypatch):
    path, _ = box

    def down(url, cafile=None, quiet=False):
        raise OSError("connection refused")
    monkeypatch.setattr(core, "test_ctem", down)
    with pytest.raises(SystemExit, match="new address failed"):
        setup.set_url(_args(), str(path))
    assert _url(path) == OLD


def test_every_command_and_the_installer_say_the_agent_version(capsys):
    import ctem_collector
    from api.collector.installer import agent_version, render_installer
    assert agent_version() == core.AGENT_VERSION
    script = render_installer("https://ctem.acme.example", "", "box1")
    assert f"AGENT_VERSION='{core.AGENT_VERSION}'" in script and "@@AGENT_VERSION@@" not in script
    assert 'say "open-ctem shipper installer, agent version $AGENT_VERSION"' in script
    with pytest.raises(SystemExit):
        ctem_collector.main(["--version"])
    assert core.AGENT_VERSION in capsys.readouterr().out
    assert ctem_collector.main(["test-ctem", "--url", "http://not-https.acme.example"]) == 1
    assert capsys.readouterr().err.startswith(f"open-ctem shipper {core.AGENT_VERSION}")
