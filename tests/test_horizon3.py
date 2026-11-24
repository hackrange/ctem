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
    # Addresses no other test's asset has (the test networks are small and shared)
    used = set((await db.execute(select(Device.ip_hash))).scalars())
    free = [a for net in ("198.51.100", "192.0.2", "203.0.113") for a in (f"{net}.{i}" for i in range(1, 255)) if search_hash(a) not in used]
    pick = int(n[:2], 16) % (len(free) - 4)
    ip, alias_ip, quiet_ip, printer_ip = free[pick:pick + 4]
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
        if "weakness_series_page" in query:   # a tenant without them: the pentests' own weaknesses are read
            raise ValueError("Horizon3: Cannot query field \"weakness_series_page\" on type \"Query\".")
        if "pentests_page" in query:
            return {"pentests_page": {"pentests": [] if page > 1 else [
                {"op_id": "op1", "op_type": "NodeZero", "name": "Internal pentest", "state": "done", "completed_at": now[:19]},
                {"op_id": "op0", "name": "Running one", "state": "running", "completed_at": None}]}}
        if "weaknesses_page" in query:
            return {"weaknesses_page": {"weaknesses": [] if page > 1 else [
                {"uuid": "w1", "vuln_id": cve, "vuln_name": "SMB flaw", "vuln_aliases": [cve], "vuln_cisa_kev": True, "base_score": 9.0,
                 "ip": ip, "host_name": d.hostname, "has_proof": True, "impact_paths_count": 3},
                {"uuid": "w2", "vuln_id": "H3-2026-0001", "vuln_name": "Default credentials", "ip": printer_ip,
                 "host_name": f"printer-{n}", "has_proof": True}]}}
        if "hosts_page" in query:
            return {"hosts_page": {"hosts": [] if page > 1 else [
                {"ip": alias_ip, "ip_addresses": [alias_ip, ip], "host_name": f"alias-{n}", "host_names": [f"alias-{n}"], "is_in_scope": True,
                 "score": 10.0, "severity": "CRITICAL", "os_names": ["Windows"], "is_domain_controller": True, "services_count": 3,
                 "weaknesses_count": 1, "credentials_count": 1},
                {"ip": quiet_ip, "ip_addresses": [], "host_name": f"quiet-{n}", "host_names": [], "is_in_scope": True,
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


@pytest.mark.asyncio
async def test_a_deadlock_is_retried(monkeypatch):
    from sqlalchemy.exc import DBAPIError

    from api.integrations.horizon3 import Horizon3Connector
    calls = []

    class Apply:
        @staticmethod
        async def op(db, *a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise DBAPIError("UPDATE devices", {}, Exception("deadlock detected"))
            return 7

    class Db:
        async def rollback(self):
            calls.append("rollback")
    async def no_wait(_):
        return None
    monkeypatch.setattr("asyncio.sleep", no_wait)
    assert await Horizon3Connector({"api_key": "k"})._apply(Db(), Apply, {"op_id": "x"}, [], None, {}) == 7
    assert calls == [1, "rollback", 1]


@pytest.mark.asyncio
async def test_a_database_failure_never_puts_sql_on_the_card(db, monkeypatch):
    from sqlalchemy.exc import DBAPIError

    from api.integrations import base
    from api.models.integration import IntegrationConfig, Vendor

    class Boom:
        integration_id = None

        async def sync(self, _db):
            raise DBAPIError("UPDATE devices SET pentest=$1", {"secret": "row data"}, Exception("deadlock detected"))

    monkeypatch.setattr(base, "get_connector", lambda *a: Boom())
    cfg = IntegrationConfig(vendor=Vendor.horizon3, name="nodezero", is_enabled=True, config={})
    db.add(cfg)
    await db.commit()
    assert await base._sync_by_id(db, str(cfg.id)) is False
    await db.refresh(cfg)
    assert "deadlock" in cfg.last_sync_error and "UPDATE" not in cfg.last_sync_error and "row data" not in cfg.last_sync_error


@pytest.mark.asyncio
async def test_open_weakness_series_are_findings_whichever_pentest_saw_them(db, client_admin, monkeypatch):
    from api.core.encryption import search_hash
    from api.integrations.horizon3 import Horizon3Connector
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    n = uuid.uuid4().hex[:6]
    # Two addresses no other test's asset has (the test networks are small and shared)
    used = set((await db.execute(select(Device.ip_hash))).scalars())
    free = [a for a in (f"198.51.100.{i}" for i in range(1, 255)) if search_hash(a) not in used]
    ip, camera = free[int(n[:2], 16) % (len(free) - 1)], free[-1]
    d = Device(hostname=f"srv-s-{n}", device_type=DeviceType.server, ip=ip, ip_hash=search_hash(ip))
    cve = f"CVE-2017-{1000 + int(n[2:5], 16) % 8999}"
    scan = Vulnerability(source="t_h3s", source_vuln_id=f"s{n}", cve_id=cve, title="Scanner view", attack_vector="network")
    gone = Vulnerability(source="horizon3", source_vuln_id=f"H3-OLD-{n}", title="Fixed since")
    db.add_all([d, scan, gone])
    await db.flush()
    other = Finding(device_id=d.id, vuln_id=scan.id, source="t_h3s", exposure="listening", ports="445/tcp")
    stale = Finding(device_id=d.id, vuln_id=gone.id, source="horizon3", source_id=f"{d.id}:H3-OLD-{n}")
    db.add_all([other, stale])
    await db.commit()
    now = datetime.now(timezone.utc).isoformat()[:19]

    def ser(vid, at, port, first="2026-06-14T16:45:02"):
        return {"uuid": f"{vid}-{at}-{port}", "vuln_id": vid, "vuln_name": "Camera auth bypass", "severity": "CRITICAL", "score": 9.8,
                "ip": at, "port": port, "protocol": "tcp", "status": "OPEN", "is_open": True, "first_seen_at": first,
                "last_seen_at": "2026-06-15T23:14:19", "last_op_id": "june", "attack_paths_count": 1,
                "vuln": {"aliases": [], "cisa_kev": True, "known_ransomware_campaign_use": False, "base_score": 9.8}}

    async def gql(self, client, query, variables=None):
        page = (variables or {}).get("page_input", {}).get("page_num", 1)
        if "weakness_series_page" in query:
            assert variables["page_input"]["filter_by_inputs"] == [{"field_name": "status", "values": ["OPEN"]}]
            return {"weakness_series_page": {"weakness_series": [] if page > 1 else [
                ser(cve, ip, 445), ser(cve, ip, 139), ser(cve, camera, 65014), ser(cve, camera, 65002)]}}
        if "pentests_page" in query:
            return {"pentests_page": {"pentests": [] if page > 1 else [
                {"op_id": "nov", "op_type": "NodeZero", "name": "November", "state": "done", "completed_at": now},
                {"op_id": "june", "op_type": "NodeZero", "name": "June", "state": "done", "completed_at": "2026-06-15T23:14:19",
                 "impacts_count": 1}]}}
        if "attack_paths_page" in query:
            assert "mutation" not in query
            if variables["op_id"] != "june" or page > 1:
                return {"attack_paths_page": {"attack_paths": []}}
            g = {"nodes": [{"uuid": "w", "label": "Weakness", "description": f"NodeZero module dahua found {cve} on {camera}:65002", "created_at": "2026-06-15T01:00:00"},
                           {"uuid": "nz", "label": "NodeZero", "description": "NodeZero was launched from host 203.0.113.9", "created_at": "2026-06-14T16:00:00"},
                           {"uuid": "imp", "label": "ImpactEdge", "description": "Camera takeover", "created_at": None},
                           {"uuid": "h", "label": "Address", "description": f"NodeZero module host_discovery discovered host {camera}", "created_at": "2026-06-14T16:01:00"}],
                 "edges": [{"source": "w", "target": "imp"}, {"source": "nz", "target": "h"}, {"source": "h", "target": "w"}]}
            return {"attack_paths_page": {"attack_paths": [{"uuid": "HostCompromise/w", "attack_path_title": "Camera auth bypass", "score": 9.8,
                    "severity": "CRITICAL", "impact_type": "HostCompromise", "impact_title": "Host Compromise", "impact_description": "Full control of the device",
                    "time_to_finding_s": 3600, "hosts": [{"ip": camera, "host_name": None}], "weaknesses": [{"uuid": "w", "vuln_id": cve, "ip": camera, "port": 65002}],
                    "attack_vector": {"attack_graph": g}}]}}
        if "weaknesses_page" in query:
            if page > 1:
                return {"weaknesses_page": {"weaknesses": []}}
            if variables["op_id"] == "june":   # months old, outside the window: asked only for what it proved
                assert variables["page_input"]["filter_by_inputs"] == [{"field_name": "has_proof", "values": ["true"]}]
                return {"weaknesses_page": {"weaknesses": [{"vuln_id": cve, "ip": camera, "port": 65002, "time_to_finding_s": 116_748,
                        "proofs": [{"proof_type": "CommandOutputProofResource", "created_at": "2026-06-15T03:54:15",
                                    "command_outputs": [{"command": "nuclei -l urls.txt",
                                                         "output": "POST /RPC2_Login\nCookie: s=abc\nsession: " + "Z" * 40}]}]}]}}
            return {"weaknesses_page": {"weaknesses": [{"vuln_id": cve, "ip": ip, "has_proof": True}]}}
        if "services_page" in query:
            return {"services_page": {"services": [] if page > 1 else [{"ip": ip, "port": 445, "protocol": "TCP"}, {"ip": ip, "port": 139}]}}
        if "hosts_page" in query:
            return {"hosts_page": {"hosts": [] if page > 1 else [{"ip": ip, "ip_addresses": [ip], "is_in_scope": True, "services_count": 2}]}}
        return {k: {} for k in ("credentials_page", "data_stores_page")}
    monkeypatch.setattr(Horizon3Connector, "_gql", gql)

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False
    monkeypatch.setattr("api.integrations.horizon3.safe_client", lambda **k: Client())
    assert await Horizon3Connector({"api_key": "k", "region": "us"}).sync(db) >= 2

    def fresh(model, *where):
        return select(model).where(*where).execution_options(populate_existing=True)
    # The scanner has the same CVE open there: one finding (the scanner's, now reachable); NodeZero's is kept, merged,
    # with its ports and proof for the Pentest tab
    mine = (await db.execute(fresh(Finding, Finding.source == "horizon3", Finding.device_id == d.id, Finding.status == FindingStatus.merged))).scalars().all()
    assert len(mine) == 1 and mine[0].ports == "139/tcp 445/tcp" and mine[0].details["has_proof"] and mine[0].is_reachable is True
    assert not (await db.execute(fresh(Finding, Finding.source == "horizon3", Finding.device_id == d.id,
                                       Finding.status == FindingStatus.open))).scalars().all()
    assert (await db.execute(fresh(Finding, Finding.id == stale.id))).scalar_one_or_none() is None   # no longer open: gone, not history
    assert (await db.execute(fresh(Finding, Finding.id == other.id))).scalar_one().is_reachable is True    # same CVE, other source
    cam = (await db.execute(select(Device).where(Device.ip_hash == search_hash(camera)))).scalar_one()      # seen in June only: an asset
    cf = (await db.execute(fresh(Finding, Finding.source == "horizon3", Finding.device_id == cam.id))).scalar_one()
    assert cf.status == FindingStatus.open and cf.ports == "65002/tcp 65014/tcp" and cf.details["has_proof"] is True and cf.is_reachable
    v = (await db.execute(fresh(Vulnerability, Vulnerability.source == "horizon3", Vulnerability.source_vuln_id == cve))).scalar_one()
    assert v.is_kev and v.cvss_base == 9.8 and v.pentest_exploited
    assert (await db.execute(fresh(Vulnerability, Vulnerability.id == scan.id))).scalar_one().pentest_exploited   # same CVE, scanner's entry
    assert not (await db.execute(fresh(Vulnerability, Vulnerability.id == gone.id))).scalar_one().pentest_exploited
    r = await client_admin.get("/api/v1/vulns", params={"exploited": "true", "q": cve, "sort": "pentest_exploited", "order": "desc"})
    assert r.status_code == 200 and {x["source"] for x in r.json()["vulns"]} == {"horizon3", "t_h3s"}
    assert all(x["pentest_exploited"] for x in r.json()["vulns"])
    # How it was proved, kept on the finding (its details are encrypted), with credentials masked
    pr = cf.details["proof"]
    assert pr["pentest"] == "June" and pr["found_after_s"] == 116_748 and pr["port"] == 65002
    assert pr["steps"][0]["command"] == "nuclei -l urls.txt"
    assert "Cookie: [redacted]" in pr["steps"][0]["output"] and "Z" * 40 not in pr["steps"][0]["output"]
    # The June attack path through the camera, as the chain NodeZero walked, still active while its weakness is open
    from api.models.risk import AttackPath
    path = (await db.execute(fresh(AttackPath, AttackPath.target_device_id == cam.id, AttackPath.confirmed_by == "horizon3"))).scalar_one()
    assert path.is_active and path.path_score == 9.8 and path.external_id == "june:HostCompromise/w"
    assert [s["kind"] for s in path.graph["steps"]] == ["NodeZero", "Address", "Weakness", "Impact"]
    assert path.graph["steps"][1]["assets"] == {camera: str(cam.id)}
    r = await client_admin.get(f"/api/v1/devices/{cam.id}/pentest")
    body = r.json()
    assert r.status_code == 200 and body["chains"][0]["impact"] == "Host Compromise" and "pairs" not in body["chains"][0]
    g = body["graphs"]["all"]   # the paths as a map: launch, host, weakness, impact, left to right
    assert [n["kind"] for n in sorted(g["nodes"], key=lambda n: n["x"])] == ["launch", "host", "weakness", "impact"]
    assert body["graphs"]["each"][0]["nodes"] and all(e["label"] for e in g["edges"])
    assert body["findings"][0]["proof"]["steps"][0]["command"] == "nuclei -l urls.txt"
    from api.integrations import horizon3_story as story
    # NodeZero closes every weakness: the path is deleted, and an asset only NodeZero knew with nothing left goes too
    from datetime import timedelta as _td
    ghost = Device(hostname=f"ghost-{n}", device_type=DeviceType.unknown, sources=",horizon3,")
    kept = Device(hostname=f"kept-{n}", device_type=DeviceType.unknown, sources=",horizon3,rapid7_insightvm,")
    db.add_all([ghost, kept])
    await db.commit()
    ghost_id, kept_id, path_id = ghost.id, kept.id, path.id
    got = await story.prune(db, set(), datetime.now(timezone.utc) - _td(days=30))
    assert got["paths"] >= 1 and got["assets"] >= 1
    assert (await db.execute(fresh(AttackPath, AttackPath.id == path_id))).scalar_one_or_none() is None
    assert (await db.execute(fresh(Device, Device.id == ghost_id))).scalar_one_or_none() is None
    assert (await db.execute(fresh(Device, Device.id == kept_id))).scalar_one_or_none() is not None   # another tool knows it
    assert (await db.execute(fresh(Device, Device.id == cam.id))).scalar_one_or_none() is not None    # its finding is still open
    dev = (await db.execute(fresh(Device, Device.id == d.id))).scalar_one()
    assert dev.pentest["open_services"] == [{"port": 445, "protocol": "tcp"}, {"port": 139, "protocol": "tcp"}]


def test_only_read_only_queries_reach_horizon3():
    from api.integrations.horizon3 import read_only
    assert read_only("query q { pentests_page { pentests { op_id } } }")
    assert read_only("{ pentests_page { pentests { op_id } } }")
    for bad in ("mutation m { cancel_op(op_id: \"x\") { op_id } }", "  # just reading\nmutation m { create_op { op_id } }",
                "query q { a } mutation m { delete_agent { uuid } }", "subscription s { ops { op_id } }"):
        with pytest.raises(PermissionError):
            read_only(bad)


def test_steps_follow_the_edges_from_the_launch():
    from api.integrations.horizon3_story import redact, steps_of
    g = {"nodes": [{"uuid": "b", "label": "Service", "description": "web on 192.0.2.5:443"}, {"uuid": "a", "label": "NodeZero"},
                   {"uuid": "c", "label": "ImpactEdge", "description": "Host Compromise"}],
         "edges": [{"source": "b", "target": "c"}, {"source": "a", "target": "b"}]}
    assert [s["kind"] for s in steps_of(g)] == ["NodeZero", "Service", "Impact"]
    assert steps_of(g)[1]["ips"] == ["192.0.2.5"]
    assert steps_of(None) == []
    assert redact("Authorization: Bearer abc", 100) == "Authorization: [redacted]"
    assert redact("x" * 50, 10).endswith("…")



def test_a_path_is_real_only_while_its_weakness_is_open_or_its_credentials_are_recent():
    from datetime import timedelta

    from api.integrations.horizon3_story import is_active
    now = datetime.now(timezone.utc)
    recent = now - timedelta(days=30)
    open_ = {("192.0.2.5", "CVE-2021-33044")}
    assert is_active([("192.0.2.5", "CVE-2021-33044")], "2026-01-01T00:00:00", open_, recent)    # weakness still open, however old
    assert not is_active([("192.0.2.5", "CVE-2020-0001")], now.isoformat(), open_, recent)      # its weakness is fixed
    assert is_active([], (now - timedelta(days=3)).isoformat(), open_, recent)                  # credentials, recent pentest
    assert not is_active([], (now - timedelta(days=90)).isoformat(), open_, recent)             # credentials, old pentest
    assert is_active([], None, None, recent)                                                    # no series: nothing to judge by
