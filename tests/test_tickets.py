"""Tests for ServiceNow ticket creation from findings."""
from __future__ import annotations

import uuid
import pytest


@pytest.mark.asyncio
async def test_create_ticket_requires_auth(client_no_auth):
    r = await client_no_auth.post(
        f"/api/v1/vulns/findings/{uuid.uuid4()}/ticket",
        json={"method": "email", "notes": "test"},
    )
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_create_ticket_bad_uuid(client_cyber):
    r = await client_cyber.post(
        "/api/v1/vulns/findings/not-a-uuid/ticket",
        json={"method": "email"},
    )
    assert r.status_code in (404, 422)


@pytest.mark.asyncio
async def test_create_ticket_nonexistent_finding(client_cyber):
    r = await client_cyber.post(
        f"/api/v1/vulns/findings/{uuid.uuid4()}/ticket",
        json={"method": "email"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_tickets_requires_auth(client_no_auth):
    r = await client_no_auth.get(f"/api/v1/vulns/findings/{uuid.uuid4()}/tickets")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_tickets_bad_uuid(client_cyber):
    r = await client_cyber.get("/api/v1/vulns/findings/not-a-uuid/tickets")
    assert r.status_code in (404, 422)


@pytest.mark.asyncio
async def test_list_tickets_nonexistent_finding(client_cyber):
    r = await client_cyber.get(f"/api/v1/vulns/findings/{uuid.uuid4()}/tickets")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_tickets_happy_path(client_cyber, db):
    """Finding with no tickets returns an empty list, not 404."""
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability

    vuln = Vulnerability(id=str(uuid.uuid4()), source="test", title="Ticket Test CVE", cve_id="CVE-2024-55555",
                         cvss_base=7.5, is_kev=False, exploit_available=False)
    device = Device(id=str(uuid.uuid4()), hostname="ticket-test-host",
                    device_type=DeviceType.server, is_internet_exposed=False)
    db.add(vuln); db.add(device)
    await db.flush()

    finding = Finding(id=str(uuid.uuid4()), device_id=device.id, vuln_id=vuln.id,
                      source="test", status=FindingStatus.open)
    db.add(finding)
    await db.commit()

    r = await client_cyber.get(f"/api/v1/vulns/findings/{finding.id}/tickets")
    assert r.status_code == 200
    d = r.json()
    assert "tickets" in d
    assert isinstance(d["tickets"], list)
