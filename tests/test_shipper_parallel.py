"""Shipper 1.5.0: sources run side by side, each with its own lock, state and error, and the units that start them."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))


def test_sources_run_side_by_side_with_their_own_lock_and_state(tmp_path, monkeypatch):
    import fcntl

    import ctem_collector as agent
    import json as _json
    monkeypatch.setattr(agent.core, "STATE_DIR", str(tmp_path))
    (tmp_path / "state.json").write_text(_json.dumps({"last_by_kind": {"ldap": 0, "crowdstrike": 0}, "cs_x": 1}))
    shipped, checkins = [], []

    class Sh:
        api = None

        def checkin(self, errors=None, ran=False):
            checkins.append(errors)
            return {"schedule_minutes": 5}

        def modules(self):
            return [{"kind": "ldap", "integration_id": "i1", "settings": {}}, {"kind": "crowdstrike", "integration_id": "i2", "settings": {}}]

        def secrets(self):
            return {"ldap": {"password": "p"}, "crowdstrike": {"client_secret": "s"}}, {}

        def settings_for(self, m):
            return {}
    monkeypatch.setattr(agent.core, "Shipper", Sh)

    def ship(api, m, s, secret, state):
        if m["kind"] == "crowdstrike":
            raise RuntimeError("falcon down")
        shipped.append(m["kind"])
        return 1
    monkeypatch.setattr(agent, "ship", ship)
    # crowdstrike is already running elsewhere: only ldap runs here
    with open(tmp_path / "run.crowdstrike.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert agent.run() == 0 and shipped == ["ldap"]
    st = _json.loads((tmp_path / "state.ldap.json").read_text())
    assert st["last_by_kind"]["ldap"] > 0 and st["cs_x"] == 1            # seeded from the old shared state
    assert not (tmp_path / "state.crowdstrike.json").exists()
    # now crowdstrike runs, fails, and reports only its own error
    assert agent.run(only="crowdstrike") == 1 and "falcon down" in checkins[-1]["crowdstrike"]
    assert _json.loads((tmp_path / "state.crowdstrike.json").read_text())["errors"]["crowdstrike"].endswith("falcon down")
    # an older shipper's run holding the shared lock: wait for it
    with open(tmp_path / "run.lock", "w") as old:
        fcntl.flock(old, fcntl.LOCK_EX | fcntl.LOCK_NB)
        n = len(checkins)
        assert agent.run(force=True) == 0 and len(checkins) == n


def test_installer_writes_a_unit_per_source_and_starts_each():
    from pathlib import Path

    import ctem_collector as agent
    sh = (Path(agent.__file__).parent / "install.sh").read_text()
    assert "SOURCES='ldap rapid7_console crowdstrike splunk netprobe'" in sh and "-source@.service" in sh
    assert "ctem_collector.py run --only %i" in sh and "for k in %s; do systemctl start --no-block %s-source@$k.service; done" in sh
    assert set(agent.core.MODULES) == {"ldap", "rapid7_console", "crowdstrike", "splunk", "netprobe"}   # the installer's list matches
