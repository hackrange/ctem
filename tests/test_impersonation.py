"""Admin > Users > View as: an admin sees CTEM as one person does, read-only, for 30 minutes, all in the Audit Log."""
from __future__ import annotations

import re
import time
import uuid

import pytest
from sqlalchemy import select

from api.auth import sso_config
from api.auth.local import hash_password
from api.core.config import get_settings
from api.models.user import User, UserRole

PW = "correct horse battery staple"


@pytest.fixture(autouse=True)
def _local_sign_in(monkeypatch):
    async def local_only(db):
        return "local_only", None
    monkeypatch.setattr(sso_config, "effective", local_only)
    monkeypatch.setattr(get_settings(), "mfa_required", False)


async def _account(db, role, **kw):
    u = User(username=f"va{role}{uuid.uuid4().hex[:6]}", is_local=True, is_active=True, password_hash=hash_password(PW), **kw)
    db.add(u)
    await db.flush()
    db.add(UserRole(user_id=u.id, role_name=role))
    await db.commit()
    return u


async def _login(client, name):
    client.base_url = "https://test"
    client.cookies.clear()
    page = await client.get("/login")
    csrf = re.search(r'name="_csrf" value="([^"]*)"', page.text).group(1)
    r = await client.post("/auth/login", data={"username": name, "password": PW, "_csrf": csrf})
    assert r.status_code in (302, 303)


async def _me(client):
    return (await client.get("/api/v1/impersonate")).json()


async def test_view_as_is_read_only_audited_and_ends(client, db):
    from api.models.settings import AuditLog
    admin, person, other_admin = await _account(db, "admin"), await _account(db, "read_only"), await _account(db, "admin")
    await _login(client, admin.username)
    url = f"/api/v1/admin/users/{person.id}/impersonate"
    assert (await client.post(url, json={"reason": "x"})).status_code == 422            # a reason is required
    assert (await client.post(f"/api/v1/admin/users/{other_admin.id}/impersonate", json={"reason": "check access"})).status_code == 400
    assert (await client.post(f"/api/v1/admin/users/{admin.id}/impersonate", json={"reason": "check access"})).status_code == 400
    assert (await client.post(f"/api/v1/admin/users/{uuid.uuid4()}/impersonate", json={"reason": "check access"})).status_code == 404
    r = await client.post(url, json={"reason": "ticket 42: can't see devices"})
    assert r.status_code == 200 and r.json()["until"] > time.time()

    s = await _me(client)
    assert s["active"] and s["viewing_as"] == person.username and s["by"] == admin.username
    assert (await client.get("/api/v1/admin/users")).status_code == 403               # sees what the person sees
    page = await client.get("/")
    assert "Viewing as" in page.text and person.username in page.text
    w = await client.put("/api/v1/me/hidden", json={"kind": "alert", "id": "threat_alert_x" * 2, "hidden": True})
    assert w.status_code == 403 and "read-only" in w.json()["detail"]                 # no writes as them
    assert (await client.post(url, json={"reason": "nested"})).status_code == 403    # no view-as inside view-as

    assert (await client.post("/api/v1/impersonate/stop")).status_code == 200
    assert (await _me(client))["active"] is False
    assert (await client.get("/api/v1/admin/users")).status_code == 200               # back to the admin
    rows = (await db.execute(select(AuditLog).where(AuditLog.resource_id == str(person.id)))).scalars().all()
    assert {r.action for r in rows} >= {"impersonate.start", "impersonate.stop"}
    assert all(r.actor_user_id == str(admin.id) for r in rows) and any("ticket 42" in (r.detail or "") for r in rows)


async def test_view_as_ends_on_time_or_when_the_admin_loses_the_role(client, db):
    from api.models.settings import AuditLog
    admin, person = await _account(db, "admin"), await _account(db, "cyber")
    await _login(client, admin.username)
    url = f"/api/v1/admin/users/{person.id}/impersonate"
    assert (await client.post(url, json={"reason": "check access"})).status_code == 200
    person.is_active = False   # disabled meanwhile: the view ends
    await db.commit()
    assert (await _me(client))["active"] is False
    person.is_active = True
    await db.commit()
    assert (await client.post(url, json={"reason": "check access"})).status_code == 200
    role = (await db.execute(select(UserRole).where(UserRole.user_id == admin.id))).scalar_one()
    await db.delete(role)
    await db.commit()
    db.expire_all()   # the test shares one session; a real request loads the roles fresh
    assert (await _me(client))["active"] is False
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "impersonate.expired",
                                                    AuditLog.actor_user_id == str(admin.id)))).scalars().all()


async def test_api_tokens_cannot_view_as(client_admin, cyber_user):
    r = await client_admin.post(f"/api/v1/admin/users/{cyber_user.id}/impersonate", json={"reason": "check access"},
                                headers={"Authorization": "Bearer " + "a" * 64})
    assert r.status_code in (401, 403)
