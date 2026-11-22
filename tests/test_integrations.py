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


@pytest.mark.asyncio
async def test_editing_an_integration_keeps_saved_credentials(db, client_admin):
    """Changing the schedule or a setting never asks for credentials again; moving the endpoint still does.
    Shipper-run integrations aren't edited here at all."""
    from api.models.integration import IntegrationConfig, Vendor
    shipper = IntegrationConfig(vendor=Vendor.rapid7_insightvm, name="Console via shipper", is_enabled=True,
                                config={"mode": "collector", "collector": "abc"})
    direct = IntegrationConfig(vendor=Vendor.rapid7_insightvm, name="Console direct", is_enabled=True,
                               config={"mode": "console", "host": "r7.acme.example", "username": "svc", "password": "s3cret"})
    db.add_all([shipper, direct])
    await db.flush()
    from api.models.collector import CollectorProfile
    prof = CollectorProfile(name=f"box-{shipper.id}"[:60], created_by="test", config_version=1,
                            modules={"insightvm_console": {"integration_id": str(shipper.id), "enabled": True}})
    db.add(prof)
    await db.commit()
    listed = {i["id"]: i for i in (await client_admin.get("/api/v1/integrations")).json()["integrations"]}
    assert listed[str(shipper.id)]["shipper_managed"] and not listed[str(direct.id)]["shipper_managed"]
    # what the edit form sends for the shipper one: blank host and username, the sentinel for unsaved secrets
    form = {"mode": "console", "host": "", "username": "", "password": "__REDACTED__", "api_key": "__REDACTED__",
            "min_severity": "Critical"}
    # a shipper-run integration is managed on the Shippers tab only: the integration routes leave it alone
    r = await client_admin.put(f"/api/v1/integrations/{shipper.id}", json={"config": form, "sync_schedule": "0 */6 * * *"})
    assert r.status_code == 409 and "Shippers" in r.text
    assert (await client_admin.delete(f"/api/v1/integrations/{shipper.id}")).status_code == 409
    await db.refresh(shipper)
    assert shipper.config == {"mode": "collector", "collector": "abc"}
    # once the shipper no longer owns it, its leftover card can be cleaned up
    await db.delete(prof)
    await db.commit()
    assert (await client_admin.delete(f"/api/v1/integrations/{shipper.id}")).status_code == 200
    # the direct one: same host (blank vs trailing slash and case don't count as a move), secret kept
    r = await client_admin.put(f"/api/v1/integrations/{direct.id}", json={"config": {
        "mode": "console", "host": "R7.acme.example/", "username": "svc", "password": "__REDACTED__", "api_key": "__REDACTED__",
        "port": ""}})
    assert r.status_code == 200, r.text
    await db.refresh(direct)
    assert direct.config["password"] == "s3cret" and "api_key" not in direct.config   # never the sentinel
    # a real move with a kept secret is refused, so a saved password can't be sent somewhere else
    r = await client_admin.put(f"/api/v1/integrations/{direct.id}", json={"config": {
        "mode": "console", "host": "evil.example", "username": "svc", "password": "__REDACTED__"}})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_browser_sessions_renew_while_in_use_and_end_at_the_hard_limit(monkeypatch):
    import time
    from types import SimpleNamespace

    from fastapi import HTTPException
    import jwt

    from api.auth import middleware as mw
    s = mw._settings()
    user = SimpleNamespace(id="u1", username="pat")
    now = int(time.time())
    # half the life gone: a fresh token, so active work never hits the 15 minutes
    req = SimpleNamespace(session={"access_token": "old", "signed_in_at": now - 60})
    mw._slide(req, {"exp": now + 60}, user)
    fresh = jwt.decode(req.session["access_token"], s.secret_key, algorithms=[s.jwt_algorithm])
    assert fresh["sub"] == "u1" and fresh["exp"] > now + 60
    # plenty left: nothing changes
    req = SimpleNamespace(session={"access_token": "keep", "signed_in_at": now - 60})
    mw._slide(req, {"exp": now + s.access_token_expire_minutes * 60}, user)
    assert req.session["access_token"] == "keep"
    # past the hard limit: signed out however busy
    req = SimpleNamespace(session={"access_token": "x", "signed_in_at": now - s.session_max_hours * 3600 - 5})
    with pytest.raises(HTTPException) as e:
        mw._slide(req, {"exp": now + 600}, user)
    assert e.value.status_code == 401 and req.session == {}
