"""Ticket dialog helpers: configured methods and copy-ready preview text."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_options_only_offer_what_is_configured(client_admin, db):
    from sqlalchemy import func, select

    from api.models.integration import IntegrationConfig, Vendor

    have = (await db.execute(select(func.count()).select_from(IntegrationConfig).where(
        IntegrationConfig.vendor == Vendor.servicenow, IntegrationConfig.is_enabled.is_(True)))).scalar_one()
    opts = (await client_admin.get("/api/v1/vulns/findings/ticket-options")).json()
    assert opts == {"api": have > 0, "email": False, "copy": True}  # email is off unless EMAIL_MODE + inbound address

    db.add(IntegrationConfig(vendor=Vendor.servicenow, name="ACME ServiceNow", is_enabled=True, config={}))
    await db.commit()
    assert (await client_admin.get("/api/v1/vulns/findings/ticket-options")).json()["api"] is True


async def _finding(db, hostname="ticket.acme.example"):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability

    dev = Device(hostname=hostname, device_type=DeviceType.server, source="t_ticket")
    vuln = Vulnerability(cve_id="CVE-2026-4242", title="Acme widget overflow", cvss_base=9.1, source="t_ticket")
    db.add_all([dev, vuln])
    await db.flush()
    f = Finding(device_id=dev.id, vuln_id=vuln.id, source="t_ticket", status=FindingStatus.open)
    db.add(f)
    await db.commit()
    return f


@pytest.mark.asyncio
async def test_preview_has_subject_body_and_notes(client_admin, db):
    f = await _finding(db)
    data = (await client_admin.get(f"/api/v1/vulns/findings/{f.id}/ticket/preview",
                                   params={"notes": "Patch window Friday", "assignment_group": "ACME SecOps"})).json()
    assert "CVE-2026-4242" in data["subject"] and "ticket.acme.example" in data["subject"]
    assert data["body"].startswith("Assignment group: ACME SecOps")
    assert "Patch window Friday" in data["body"]


@pytest.mark.asyncio
async def test_preview_respects_device_access(client_it_user, db):
    f = await _finding(db, "hidden-ticket.acme.example")
    resp = await client_it_user.get(f"/api/v1/vulns/findings/{f.id}/ticket/preview")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_preview_limits_input(client_admin, db):
    f = await _finding(db, "limits.acme.example")
    resp = await client_admin.get(f"/api/v1/vulns/findings/{f.id}/ticket/preview", params={"notes": "x" * 2001})
    assert resp.status_code == 422
