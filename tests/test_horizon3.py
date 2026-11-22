"""Horizon3 NodeZero: weaknesses as findings, proof marks other sources reachable, a closed port means unreachable."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select


@pytest.mark.asyncio
async def test_nodezero_findings_proof_and_closed_ports(db, monkeypatch):
    from api.core.encryption import search_hash
    from api.integrations.horizon3 import Horizon3Connector
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    from api.scoring.compensating import ControlContext, port_closed_note, reachability
    n = uuid.uuid4().hex[:6]
    ip = f"198.51.100.{int(n[:2], 16) % 250 + 1}"
    d = Device(hostname=f"srv-h3-{n}", device_type=DeviceType.server, ip=ip, ip_hash=search_hash(ip))
    cve, other = f"CVE-2026-{7000 + int(n[2:5], 16) % 999}", f"CVE-2026-{6000 + int(n[2:5], 16) % 999}"
    v1 = Vulnerability(source="t_h3", source_vuln_id=f"a{n}", cve_id=cve, title="SMB flaw", attack_vector="network", cvss_base=9.0)
    v2 = Vulnerability(source="t_h3", source_vuln_id=f"b{n}", cve_id=other, title="RDP flaw", attack_vector="network", cvss_base=8.0)
    v3 = Vulnerability(source="t_h3", source_vuln_id=f"c{n}", cve_id=None, title="Web flaw", attack_vector="network", cvss_base=7.0)
    db.add_all([d, v1, v2, v3])
    await db.flush()
    proved = Finding(device_id=d.id, vuln_id=v1.id, source="t_h3", exposure="listening", ports="445/tcp")
    closed = Finding(device_id=d.id, vuln_id=v2.id, source="t_h3", exposure="listening", ports="3389/tcp")
    open_ = Finding(device_id=d.id, vuln_id=v3.id, source="t_h3", exposure="listening", ports="443/tcp")
    db.add_all([proved, closed, open_])
    await db.commit()
    ids = {k: str(x.id) for k, x in (("proved", proved), ("closed", closed), ("open", open_))}
    now = datetime.now(timezone.utc).isoformat()

    async def gql(self, client, query, variables=None):
        page = (variables or {}).get("page_input", {}).get("page_num", 1)
        if "pentests_page" in query:
            return {"pentests_page": {"pentests": [] if page > 1 else [
                {"op_id": "op1", "op_type": "NodeZero", "name": "Internal pentest", "state": "done", "completed_at": now[:19]},
                {"op_id": "op0", "name": "Running one", "state": "running", "completed_at": None}]}}
        if "weaknesses_page" in query:
            return {"weaknesses_page": {"weaknesses": [] if page > 1 else [
                {"uuid": "w1", "vuln_id": cve, "vuln_name": "SMB flaw", "vuln_aliases": [cve], "vuln_cisa_kev": True, "base_score": 9.0,
                 "ip": ip, "host_name": d.hostname, "has_proof": True, "impact_paths_count": 3},
                {"uuid": "w2", "vuln_id": "H3-2026-0001", "vuln_name": "Default credentials", "ip": f"203.0.113.{int(n[:2], 16) % 250 + 1}",
                 "host_name": f"printer-{n}", "has_proof": True}]}}
        if "hosts_page" in query:
            return {"hosts_page": {"hosts": [] if page > 1 else [
                {"ip": "192.0.2.200", "ip_addresses": ["192.0.2.200", ip], "host_name": f"alias-{n}", "host_names": [f"alias-{n}"], "is_in_scope": True,
                 "score": 10.0, "severity": "CRITICAL", "os_names": ["Windows"], "is_domain_controller": True, "services_count": 3,
                 "weaknesses_count": 1, "credentials_count": 1},
                {"ip": f"192.0.2.{int(n[:2], 16) % 250 + 1}", "ip_addresses": [], "host_name": f"quiet-{n}", "host_names": [], "is_in_scope": True,
                 "weaknesses_count": 0}]}}
        if "attack_paths_page" in query:
            return {"attack_paths_page": {"attack_paths": [] if page > 1 else [
                {"uuid": f"DomainCompromise/{n}", "name": "SMB flaw", "score": 9.8, "severity": "CRITICAL", "impact_type": "DomainCompromise",
                 "impact_title": "Domain Compromise", "affected_asset_text": f"Service on {ip} ({d.hostname}) Port 445", "time_to_finding_s": 600}]}}
        if "credentials_page" in query:
            return {"credentials_page": {"credentials": [] if page > 1 else [
                {"uuid": f"c{n}", "user_name": "acme\\admin", "cred_type": "STANDARD", "is_cracked": True, "has_proof": True,
                 "is_domain_admin": True, "ip": ip, "host_name": d.hostname}]}}
        if "data_stores_page" in query:
            return {"data_stores_page": {"data_stores": [] if page > 1 else [{"name": "C$", "ip": ip, "data_store_type": "FileShare"}]}}
        if "services_page" in query:
            return {"services_page": {"services": [] if page > 1 else [{"ip": ip, "port": 445}, {"ip": ip, "port": 443}]}}
        raise AssertionError(query)
    monkeypatch.setattr(Horizon3Connector, "_gql", gql)

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False
    monkeypatch.setattr("api.integrations.horizon3.safe_client", lambda **k: Client())
    c = Horizon3Connector({"api_key": "k", "region": "us"})
    assert await c.sync(db) >= 3

    def fresh(fid):
        return select(Finding).where(Finding.id == fid).execution_options(populate_existing=True)
    p = (await db.execute(fresh(ids["proved"]))).scalar_one()
    assert p.is_reachable is True and p.reachability_source == "horizon3"             # NodeZero proved this CVE here
    cl = (await db.execute(fresh(ids["closed"]))).scalar_one()
    assert cl.is_reachable is False and cl.reachability_source == "horizon3_closed"   # 3389 wasn't open when tested
    note = port_closed_note(cl)
    assert "3389" in note and "NodeZero" in note
    assert reachability(ControlContext(attack_vector="network", exposure="listening", ports="3389/tcp", port_closed=note)) == (0.0, note)
    op = (await db.execute(fresh(ids["open"]))).scalar_one()
    assert op.is_reachable is None                                                    # 443 was open: unchanged
    mine = (await db.execute(select(Finding).where(Finding.source == "horizon3", Finding.device_id == d.id))).scalars().all()
    assert len(mine) == 1 and mine[0].status == FindingStatus.open and mine[0].details["has_proof"]
    printer = (await db.execute(select(Device).where(Device.hostname == f"printer-{n}"))).scalar_one()
    assert ",horizon3," in printer.sources                                            # seen only by NodeZero: still an asset
    assert (await db.execute(select(Device).where(Device.hostname == f"quiet-{n}"))).scalar_one_or_none() is None   # nothing on it
    assert (await db.execute(select(Device).where(Device.hostname == f"alias-{n}"))).scalar_one_or_none() is None   # matched by its 2nd IP
    from api.models.alert_feed import FeedAlert
    dev = (await db.execute(select(Device).where(Device.id == d.id).execution_options(populate_existing=True))).scalar_one()
    pt = dev.pentest
    assert pt["severity"] == "CRITICAL" and pt["domain_controller"] and pt["attack_paths"][0]["impact"] == "Domain Compromise"
    assert pt["credentials"][0]["domain_admin"] and pt["data_stores"][0]["name"] == "C$" and pt["attack_paths"][0]["minutes_to_find"] == 10
    kinds = {a.kind for a in (await db.execute(select(FeedAlert).where(FeedAlert.key.like(f"%{n}%")))).scalars()}
    assert {"pentest_impact", "pentest_domain_admin"} <= kinds


def test_regions_and_bad_key_message():
    from api.integrations.horizon3 import REGIONS, Horizon3Connector
    assert REGIONS["us"].startswith("https://api.gateway.horizon3ai.com")
    assert Horizon3Connector({"api_key": "k", "region": "eu"})._base == REGIONS["eu"]
    assert Horizon3Connector({"api_key": "k"})._base == REGIONS["us"]


def test_horizon3_is_registered():
    import api.integrations  # noqa: F401 -- importing registers the connectors
    from api.integrations.base import get_connector
    assert type(get_connector("horizon3", {"api_key": "k"})).__name__ == "Horizon3Connector"
