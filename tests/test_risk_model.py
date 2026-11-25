"""The risk-based score (api/scoring/risk_model.py): likely and reachable beats severe; protections still count;
settings are clamped, admin-only, audited, and saving rescores the fleet."""
from __future__ import annotations

import pytest

from api.scoring import risk_model
from api.scoring.compensating import ControlContext


def _s(cvss=7.5, epss=0.0, kev=False, crit=0.5, device_type="server", **ctx):
    ctx.setdefault("edr_active", True)
    cfg = risk_model.merged(None)
    return risk_model.score(cvss, epss, kev, crit, ControlContext(device_type=device_type, **ctx), device_type, cfg)[0]


def test_likely_and_reachable_outranks_severe_but_out_of_reach():
    exposed_kev = _s(cvss=7.5, kev=True, exposure="listening", ports="443/tcp", is_internet_exposed=True, attack_vector="network")
    severe_local = _s(cvss=9.8, epss=0.002, attack_vector="local", exposure="local")
    physical_kev = _s(cvss=6.8, kev=True, attack_vector="physical", exposure="local")
    assert exposed_kev > 75 > severe_local
    assert physical_kev < exposed_kev / 2   # known exploited, but needs hands on the machine
    assert severe_local < 40                # a CVSS 9.8 nobody is exploiting, needing local access, is not urgent


def test_evidence_moves_the_score_the_right_way():
    base = dict(cvss=8.1, epss=0.3, attack_vector="network", exposure="listening", ports="445/tcp")
    plain = _s(**base)
    assert _s(**base, nodezero_confirmed_exploitable=True) > plain                     # a pentest exploited it
    assert _s(**base, port_closed="Not reachable: port closed") < plain / 3             # a pentest found it closed
    assert _s(**base, network_segmentation_blocks=True) < plain                        # segmentation blocks the path
    assert _s(**base, edr_active=False) > plain                                        # no EDR on the host
    assert _s(**base, is_internet_exposed=True) > plain                                # reachable from the internet
    client = dict(cvss=8.8, epss=0.2, attack_vector="network", exposure="local")
    assert _s(**client, device_type="workstation") > _s(**client, device_type="server")   # people browse on workstations
    assert _s(**client, device_type="network") > _s(**client, device_type="server")      # an appliance's flaw isn't client-side


def test_review_cases_rank_the_right_way():
    # more EPSS never lowers the score
    scores = [_s(cvss=9.8, epss=e, attack_vector="network", exposure="local") for e in (0.0005, 0.005, 0.05, 0.2, 0.5)]
    assert scores == sorted(scores) and scores[-1] == scores[-2]
    # a local-vector flaw on a live port is reachable, but doesn't get the internet-facing rung
    web = dict(cvss=7.8, epss=0.05, exposure="listening", ports="443/tcp", is_internet_exposed=True)
    assert _s(**web, attack_vector="local") < _s(**web, attack_vector="network")
    # an internet-facing host with no exposure data ranks above the same flaw on an internal one
    kev = dict(cvss=8.8, kev=True, attack_vector="network")
    assert _s(**kev, is_internet_exposed=True) > _s(**kev)
    # "reachable" from a source still keeps the segmentation discount
    cfg = risk_model.merged(None)
    seg = ControlContext(device_type="server", edr_active=True, attack_vector="local", network_segmentation_blocks=True)
    assert risk_model.reachability(cfg, seg, "server", True)[0] < cfg["reachability"]["listening"]


def test_settings_are_clamped_and_unknown_keys_dropped():
    cfg = risk_model.merged({"enabled": False, "weights": {"likelihood": 5, "impact": -1, "bogus": 1},
                             "reachability": {"listening": float("nan")}, "x": 1})
    assert cfg["enabled"] is False and cfg["weights"]["likelihood"] == 1.0 and cfg["weights"]["impact"] == 0.0
    assert "bogus" not in cfg["weights"] and "x" not in cfg
    assert cfg["reachability"]["listening"] == risk_model.DEFAULTS["reachability"]["listening"]
    for junk in ("not json", '{"weights": [1, 2]}', '{"reachability": "x"}', "[]"):   # a tampered row falls back
        import json
        try:
            raw = json.loads(junk)
        except ValueError:
            raw = None
        assert risk_model.merged(raw)["reachability"] == risk_model.DEFAULTS["reachability"]
    zero = risk_model.merged({"weights": {"likelihood": 0, "reachability": 0, "impact": 0}})
    assert zero["weights"] == risk_model.DEFAULTS["weights"]


@pytest.mark.asyncio
async def test_admin_tunes_resets_and_every_change_rescores(client_admin, client_cyber, db, monkeypatch):
    import api.core.tasks as tasks
    queued = []
    monkeypatch.setattr(tasks.post_sync_pipeline, "delay", lambda *a: queued.append(a))
    assert (await client_cyber.get("/api/v1/admin/risk-model")).status_code in (401, 403, 404)
    got = (await client_admin.get("/api/v1/admin/risk-model")).json()
    assert got["settings"]["enabled"] is True and got["defaults"] == risk_model.DEFAULTS
    body = {**got["settings"], "weights": {"likelihood": 0.6, "reachability": 0.3, "impact": 0.1}}
    assert (await client_cyber.put("/api/v1/admin/risk-model", json=body)).status_code in (401, 403, 404)
    for bad in ({**body, "extra": 1}, {**body, "weights": {**body["weights"], "impact": 2}},
                {**body, "weights": {"likelihood": 0.5}}, {**body, "weights": {**body["weights"], "impact": True}},
                {**body, "weights": {**body["weights"], "impact": "0.5"}}):
        assert (await client_admin.put("/api/v1/admin/risk-model", json=bad)).status_code == 422
    r = (await client_admin.put("/api/v1/admin/risk-model", json=body)).json()
    assert r["settings"]["weights"]["likelihood"] == 0.6 and not r["is_default"] and queued == [(None,)]
    r = (await client_admin.post("/api/v1/admin/risk-model/reset")).json()
    assert r["is_default"] and len(queued) == 2
    from sqlalchemy import select

    from api.models.settings import AuditLog
    acts = (await db.execute(select(AuditLog.detail).where(AuditLog.action == "risk_model.changed"))).scalars().all()
    assert any("reset" in a for a in acts) and any("weights.likelihood 0.45->0.6" in a for a in acts)
