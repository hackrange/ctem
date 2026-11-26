"""Admin > Roles: click a role to see who holds it (admins only)."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_role_members(client_admin, client_cyber, cyber_user):
    r = await client_admin.get("/api/v1/admin/roles/cyber/members")
    assert r.status_code == 200 and cyber_user.username in [m["username"] for m in r.json()["members"]]
    assert r.json()["role"]["name"] == "cyber" and "password" not in r.text
    assert (await client_cyber.get("/api/v1/admin/roles/cyber/members")).status_code == 403
    assert (await client_admin.get("/api/v1/admin/roles/nope_role/members")).status_code == 404
    assert (await client_admin.get("/api/v1/admin/roles/Bad-Name/members")).status_code == 422
