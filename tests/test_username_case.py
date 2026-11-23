"""Usernames sign in whatever their case."""
import re
import uuid

import pytest

from api.auth import sso_config
from api.auth.local import hash_password
from api.core.config import get_settings
from api.models.user import User, UserRole

PW = "correct horse battery staple"


@pytest.fixture(autouse=True)
def _local_sign_in(monkeypatch):
    # other tests save SSO-only settings; these are about the local form, not the MFA step after it
    async def local_only(db):
        return "local_only", None
    monkeypatch.setattr(sso_config, "effective", local_only)
    monkeypatch.setattr(get_settings(), "mfa_required", False)


def _csrf(html: str) -> str:
    return re.search(r'name="_csrf" value="([^"]*)"', html).group(1)


async def _account(db, name):
    u = User(username=name, is_local=True, is_active=True, password_hash=hash_password(PW))
    db.add(u)
    await db.flush()
    db.add(UserRole(user_id=u.id, role_name="cyber"))
    await db.commit()
    return u


async def _login(client, name, pw=PW):
    client.base_url = "https://test"
    client.cookies.clear()   # a signed-in cookie would send /login straight past the form
    page = await client.get("/login")
    return await client.post("/auth/login", data={"username": name, "password": pw, "_csrf": _csrf(page.text)})


async def test_login_ignores_username_case(client, db):
    name = f"Pat.Doe{uuid.uuid4().hex[:6]}"
    await _account(db, name)
    for typed in (name.lower(), name.upper(), f"  {name}  "):
        r = await _login(client, typed)
        assert r.status_code in (302, 303) and "Sign-in failed" not in r.text, typed
    assert "Sign-in failed" in (await _login(client, name.lower(), "wrong password here")).text


async def test_case_only_twins_need_the_exact_name(client, db):
    # older data could hold both; a lookalike name must never land in the other account
    base = f"twin{uuid.uuid4().hex[:6]}"
    await _account(db, base)
    await _account(db, base.upper())
    assert (await _login(client, base)).status_code in (302, 303)
    assert "Sign-in failed" in (await _login(client, base.capitalize())).text


async def test_new_account_name_taken_whatever_its_case(client_admin, db):
    name = f"acme{uuid.uuid4().hex[:6]}"
    await _account(db, name)
    r = await client_admin.post("/api/v1/admin/users", json={"username": name.upper(), "password": "Long-Enough-Pass-2026!",
                                                            "roles": ["read_only"]})
    assert r.status_code == 409
    # a directory record with the name doesn't count as a sign-in account
    other = f"dir{uuid.uuid4().hex[:6]}"
    db.add(User(username=other.upper(), is_local=False))
    await db.commit()
    r = await client_admin.post("/api/v1/admin/users", json={"username": other, "password": "Long-Enough-Pass-2026!",
                                                            "roles": ["read_only"]})
    assert r.status_code in (200, 201), r.text
