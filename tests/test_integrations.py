"""Tests for integration CRUD and sync endpoints."""
from __future__ import annotations

import uuid
import pytest


@pytest.mark.asyncio
async def test_list_integrations_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/integrations")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_integrations_read_only_denied(client_read_only):
    r = await client_read_only.get("/api/v1/integrations")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_integrations_cyber_allowed(client_cyber):
    r = await client_cyber.get("/api/v1/integrations")
    assert r.status_code == 200
    assert "integrations" in r.json()


@pytest.mark.asyncio
async def test_list_vendors(client_cyber):
    r = await client_cyber.get("/api/v1/integrations/vendors")
    assert r.status_code == 200
    d = r.json()
    assert "vendors" in d
    assert any(v["slug"] == "servicenow" for v in d["vendors"])


@pytest.mark.asyncio
async def test_create_integration_requires_admin(client_cyber):
    r = await client_cyber.post("/api/v1/integrations", json={
        "vendor": "servicenow",
        "name": "My SNOW",
        "is_enabled": False,
        "config": {},
    })
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_create_integration_admin_allowed(client_admin):
    r = await client_admin.post("/api/v1/integrations", json={
        "vendor": "servicenow",
        "name": "ACME ServiceNow",
        "is_enabled": False,
        "config": {"base_url": "https://example.invalid", "api_key": "k"},
    })
    assert r.status_code == 200
    d = r.json()
    assert d["vendor"] == "servicenow"
    assert "id" in d


@pytest.mark.asyncio
async def test_get_integration_nonexistent(client_cyber):
    r = await client_cyber.get(f"/api/v1/integrations/{uuid.uuid4()}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_integration_bad_uuid(client_cyber):
    r = await client_cyber.get("/api/v1/integrations/not-a-uuid")
    assert r.status_code in (404, 422)


@pytest.mark.asyncio
async def test_update_integration_requires_admin(client_cyber, db):
    from api.models.integration import IntegrationConfig, Vendor
    cfg = IntegrationConfig(id=str(uuid.uuid4()), vendor=Vendor.qualys,
                            name="Qualys Test", is_enabled=False, config={})
    db.add(cfg); await db.commit()

    r = await client_cyber.put(f"/api/v1/integrations/{cfg.id}",
                                json={"name": "Hacked", "is_enabled": True})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_delete_integration_requires_admin(client_cyber, db):
    from api.models.integration import IntegrationConfig, Vendor
    cfg = IntegrationConfig(id=str(uuid.uuid4()), vendor=Vendor.splunk,
                            name="Splunk Test", is_enabled=False, config={})
    db.add(cfg); await db.commit()

    r = await client_cyber.delete(f"/api/v1/integrations/{cfg.id}")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_delete_integration_admin(client_admin, client_cyber, db):
    from api.models.integration import IntegrationConfig, Vendor
    cfg = IntegrationConfig(id=str(uuid.uuid4()), vendor=Vendor.splunk,
                            name="Delete Me", is_enabled=False, config={})
    db.add(cfg); await db.commit()

    r = await client_admin.delete(f"/api/v1/integrations/{cfg.id}")
    assert r.status_code in (200, 204)

    # Confirm gone -- same UUID returns 404
    r2 = await client_cyber.get(f"/api/v1/integrations/{cfg.id}")
    assert r2.status_code == 404


@pytest.mark.asyncio
async def test_sync_integration_requires_admin(client_cyber, db):
    from api.models.integration import IntegrationConfig, Vendor
    cfg = IntegrationConfig(id=str(uuid.uuid4()), vendor=Vendor.qualys,
                            name="Qualys Sync", is_enabled=True, config={"base_url": "x", "api_key": "y"})
    db.add(cfg); await db.commit()

    r = await client_cyber.post(f"/api/v1/integrations/{cfg.id}/sync")
    assert r.status_code in (401, 403)


def test_ldaps_verifies_certificates_by_default(monkeypatch):
    import ssl
    from api.integrations import ldap as ldap_mod

    seen = {}

    class _Conn:
        def __init__(self, server, **kw):
            seen["tls"] = server.tls

    monkeypatch.setattr(ldap_mod, "Connection", _Conn)
    base = {"host": "ldap.acme.example.com", "bind_dn": "cn=x", "base_dn": "dc=acme", "use_tls": True}
    ldap_mod.LDAPConnector(base)._connect()
    assert seen["tls"].validate == ssl.CERT_REQUIRED
    ldap_mod.LDAPConnector({**base, "tls_skip_verify": True})._connect()
    assert seen["tls"].validate == ssl.CERT_NONE
