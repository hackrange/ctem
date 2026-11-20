"""Tests for admin user management endpoints."""
from __future__ import annotations

import uuid
import pytest


@pytest.mark.asyncio
async def test_list_users_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/admin/users")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_users_cyber_denied(client_cyber):
    r = await client_cyber.get("/api/v1/admin/users")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_users_admin_allowed(client_admin):
    r = await client_admin.get("/api/v1/admin/users")
    assert r.status_code == 200
    d = r.json()
    assert "users" in d
    assert isinstance(d["users"], list)


@pytest.mark.asyncio
async def test_toggle_user_bad_uuid(client_admin):
    r = await client_admin.patch("/api/v1/admin/users/not-a-uuid/toggle")
    assert r.status_code in (404, 422)


@pytest.mark.asyncio
async def test_toggle_user_nonexistent(client_admin):
    r = await client_admin.patch(f"/api/v1/admin/users/{uuid.uuid4()}/toggle")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_toggle_self_blocked(client_admin, admin_user):
    r = await client_admin.patch(f"/api/v1/admin/users/{admin_user.id}/toggle")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_toggle_other_user(client_admin, db):
    from api.models.user import User, UserRole
    target = User(id=str(uuid.uuid4()), username="toggleme", is_active=True, is_local=True, is_locked=False)
    db.add(target)
    db.add(UserRole(user_id=target.id, role_name="read_only"))
    await db.commit()

    r = await client_admin.patch(f"/api/v1/admin/users/{target.id}/toggle")
    assert r.status_code == 200
    assert r.json().get("is_active") is False


@pytest.mark.asyncio
async def test_assign_roles_requires_admin(client_cyber, db):
    from api.models.user import User
    target = User(id=str(uuid.uuid4()), username="roletarget", is_active=True, is_local=True, is_locked=False)
    db.add(target)
    await db.commit()
    r = await client_cyber.patch(f"/api/v1/admin/users/{target.id}/roles", json={"roles": ["read_only"]})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_admin_users_lists_only_accounts_that_sign_in(client_admin, client_cyber, client_it_user, db):
    import uuid as _uuid

    from api.models.user import User, UserRole
    tag = _uuid.uuid4().hex[:6]
    discovered = User(username=f"ad-only-{tag}", is_local=False)              # found in LDAP, never signs in
    oidc = User(username=f"sso-{tag}", is_local=False, oidc_sub=f"sub-{tag}")  # signs in through SSO
    local = User(username=f"local-{tag}", is_local=True)                       # local login / service account
    granted = User(username=f"granted-{tag}", is_local=False)                  # a role doesn't make it a login
    db.add_all([discovered, oidc, local, granted])
    await db.flush()
    db.add(UserRole(user_id=granted.id, role_name="read_only"))
    await db.commit()
    admin_names = {u["username"] for u in (await client_admin.get(f"/api/v1/admin/users?q={tag}")).json()["users"]}
    assert admin_names == {f"sso-{tag}", f"local-{tag}"}
    found = (await client_cyber.get(f"/api/v1/directory/users?q={tag}")).json()
    assert {u["username"] for u in found["users"]} == {f"ad-only-{tag}", f"granted-{tag}"} and found["total"] == 2
    assert (await client_it_user.get("/api/v1/directory/users")).status_code == 403
