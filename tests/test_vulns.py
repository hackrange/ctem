"""Tests for vulnerability inventory and per-vuln findings endpoint."""
from __future__ import annotations

import uuid
import pytest


@pytest.mark.asyncio
async def test_list_vulns_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/vulns")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_vulns_cyber_allowed(client_cyber):
    r = await client_cyber.get("/api/v1/vulns")
    assert r.status_code == 200
    d = r.json()
    assert "vulns" in d
    assert isinstance(d["vulns"], list)


@pytest.mark.asyncio
async def test_list_vulns_kev_filter(client_cyber):
    r = await client_cyber.get("/api/v1/vulns?is_kev=true")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_get_vuln_bad_uuid(client_cyber):
    r = await client_cyber.get("/api/v1/vulns/not-a-uuid")
    assert r.status_code in (404, 422)


@pytest.mark.asyncio
async def test_get_vuln_nonexistent(client_cyber):
    r = await client_cyber.get(f"/api/v1/vulns/{uuid.uuid4()}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_vuln_findings_bad_uuid(client_cyber):
    r = await client_cyber.get("/api/v1/vulns/not-a-uuid/findings")
    assert r.status_code in (404, 422)


@pytest.mark.asyncio
async def test_vuln_findings_nonexistent(client_cyber):
    r = await client_cyber.get(f"/api/v1/vulns/{uuid.uuid4()}/findings")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_vuln_findings_shape(client_cyber, db):
    from api.models.device import Device, DeviceType, RiskGrade
    from api.models.vuln import Finding, FindingStatus, Vulnerability

    vuln = Vulnerability(id=str(uuid.uuid4()), source="test", title="CVE-2024-TEST", cve_id="CVE-2024-99999",
                         cvss_base=9.0, is_kev=False, exploit_available=False)
    device = Device(id=str(uuid.uuid4()), hostname="test-host-vulns",
                    device_type=DeviceType.server, is_internet_exposed=False)
    db.add(vuln); db.add(device)
    await db.flush()

    finding = Finding(id=str(uuid.uuid4()), device_id=device.id, vuln_id=vuln.id,
                      source="qualys", status=FindingStatus.open)
    db.add(finding)
    await db.commit()

    r = await client_cyber.get(f"/api/v1/vulns/{vuln.id}/findings")
    assert r.status_code == 200
    d = r.json()
    assert "findings" in d
    assert d["total"] >= 1
    f = d["findings"][0]
    assert f["hostname"] == "test-host-vulns"
    assert "composite_score" in f


@pytest.mark.asyncio
async def test_update_finding_status_requires_auth(client_no_auth):
    r = await client_no_auth.patch(f"/api/v1/vulns/findings/{uuid.uuid4()}/status",
                                    json={"status": "remediated"})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_update_finding_status_bad_uuid(client_cyber):
    r = await client_cyber.patch("/api/v1/vulns/findings/not-a-uuid/status",
                                  json={"status": "remediated"})
    assert r.status_code in (404, 422)
