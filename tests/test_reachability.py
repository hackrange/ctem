"""Reachability from facts: what the CVSS vector needs, and where the scanner found the finding."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from api.scoring.compensating import ControlContext, apply_multipliers, reach_view, reachability


def _score(**kw):
    return apply_multipliers(60.0, ControlContext(edr_active=True, **kw))


def test_listening_service_is_not_discounted_and_says_where():
    base, _ = _score()
    listening, why = _score(exposure="listening", ports="80/tcp 443/tcp")
    assert listening == base and "Listening service 80/tcp 443/tcp" in why


def test_local_check_and_cvss_vector_discount_once_strongest_first():
    base, _ = _score()
    local, why = _score(exposure="local")
    assert local == pytest.approx(base * 0.75) and any("local check" in r for r in why)
    # AV:L wins over the local-check discount; they describe the same thing, so no stacking
    av_local, why = _score(exposure="local", attack_vector="local")
    assert av_local == pytest.approx(base * 0.5) and not any("local check" in r for r in why)
    assert _score(attack_vector="physical", exposure="listening")[0] == pytest.approx(base * 0.3)
    assert _score(attack_vector="adjacent")[0] == pytest.approx(base * 0.8)
    assert _score(attack_vector="network", exposure="local")[0] == pytest.approx(base * 0.75)


def test_unknown_and_confirmed_exploitable_are_never_discounted():
    assert reachability(ControlContext()) == (1.0, "")
    assert reachability(ControlContext(attack_vector="local", nodezero_confirmed_exploitable=True))[0] == 1.0


def test_reach_view_for_lists():
    class F:
        exposure, ports, is_reachable, reachability_source = "listening", "443/tcp", None, None
    assert reach_view(F(), False, "network")["reach"] == "Listening service 443/tcp"
    assert reach_view(F(), True, "network")["reach"].startswith("Contained")
    assert reach_view(F(), False, "local")["attack_vector"] == "local"


def test_rapid7_vector_and_port_parsing():
    from api.integrations.rapid7_insightvm import _attack_vector, _port
    assert _attack_vector({"cvss_v3_attack_vector": "NETWORK"}) == "network"
    assert _attack_vector({"cvss_v2_access_vector": "adjacent_network"}) == "adjacent"
    assert _attack_vector({"cvss_v2_access_vector": "local"}) == "local"
    assert _attack_vector({"cvss_v3_attack_vector": "weird"}) is None
    assert _port({"port": 443, "protocol": "TCP"}) == "443/tcp"
    assert _port({"port": 161, "protocol": "udp"}) == "161/udp"
    for bad in ({}, {"port": None}, {"port": 0}, {"port": 70000}, {"port": "443"}, {"port": True}):
        assert _port(bad) is None


@pytest.mark.asyncio
async def test_cloud_sync_stores_where_each_finding_was_found(db):
    from api.integrations.rapid7_insightvm import InsightVMConnector
    from api.models.vuln import Finding, Vulnerability

    tag = uuid.uuid4().hex[:8]
    vl, vn = (Vulnerability(source="rapid7_insightvm", source_vuln_id=f"php-{tag}", title="PHP flaw", cvss_base=9.8),
              Vulnerability(source="rapid7_insightvm", source_vuln_id=f"httpd-{tag}", title="httpd flaw", cvss_base=7.5))
    db.add_all([vl, vn])
    await db.commit()
    ids = {f"php-{tag}": str(vl.id), f"httpd-{tag}": str(vn.id)}
    asset = {"id": f"a-{tag}", "host_name": f"web-{tag}.acme.example", "ip": "192.0.2.10",
             "same": [{"vulnerability_id": f"php-{tag}"},
                      {"vulnerability_id": f"httpd-{tag}", "port": 443, "protocol": "TCP"},
                      {"vulnerability_id": f"httpd-{tag}", "port": 80, "protocol": "TCP"}]}
    conn = InsightVMConnector({"api_key": "k"})
    await conn._upsert_cloud([asset], ids, db)
    got = {f.vuln_id: f for f in (await db.execute(select(Finding).where(Finding.vuln_id.in_(ids.values())))).scalars()}
    assert (got[str(vl.id)].exposure, got[str(vl.id)].ports) == ("local", None)
    assert (got[str(vn.id)].exposure, got[str(vn.id)].ports) == ("listening", "80/tcp 443/tcp")

    # Incremental answers carry only new entries, so ports already known are kept
    conn.last_mode = "incremental"
    asset["same"] = [{"vulnerability_id": f"httpd-{tag}", "port": 8443, "protocol": "TCP"}]
    await conn._upsert_cloud([asset], ids, db)
    f = (await db.execute(select(Finding).where(Finding.vuln_id == str(vn.id))
                          .execution_options(populate_existing=True))).scalar_one()
    assert f.ports == "80/tcp 443/tcp 8443/tcp"
