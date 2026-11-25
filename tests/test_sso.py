"""SSO (OIDC) wizard, ID token verification, no-access role, and deep links surviving sign-in."""
from __future__ import annotations

import html
import re
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa

from api.auth.return_to import login_url_for, safe_next

EXAMPLE_PW = "Correct-Horse-9"  # example-only test credential
ISSUER = "https://acme.okta.com"
CLIENT = "0oaexampleclient"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ROGUE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ── return-to links ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["//evil.example/x", "/\\evil.example", "https://evil.example/", "javascript:alert(1)",
                                 "/login?next=/x", "/auth/sso", "/api/v1/devices", "/vulns/1\r\nX: y", "", None, "x" * 3000,
                                 "/static/js/app.js"])
def test_safe_next_refuses_anything_off_site(bad):
    assert safe_next(bad) is None


def test_safe_next_keeps_real_pages_and_queries():
    assert safe_next("/vulns/3f1c?tab=devices") == "/vulns/3f1c?tab=devices"
    assert login_url_for("/devices/abc", "x=1") == "/login?next=%2Fdevices%2Fabc%3Fx%3D1"
    assert login_url_for("/", "") == "/login"


# ── helpers ───────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def web(db, monkeypatch):
    """Browser-like client over https (the session cookie is __Host- and Secure)."""
    from api.core.config import get_settings
    from api.core.db import get_session
    from api.main import create_app
    monkeypatch.setattr(get_settings(), "public_url", "https://ctem.acme.example")
    monkeypatch.setattr(get_settings(), "mfa_required", False)
    monkeypatch.delenv("AUTH_MODE", raising=False)
    monkeypatch.delenv("OIDC_ISSUER", raising=False)

    async def _s():
        yield db
    app = create_app()
    app.dependency_overrides[get_session] = _s
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test",
                                 headers={"Origin": "https://test", "Accept": "text/html"}) as c:
        yield c


async def _local_user(db, role: str, password: str = EXAMPLE_PW):
    from api.auth.local import hash_password
    from api.models.user import User, UserRole
    u = User(username=f"{role}-{uuid.uuid4().hex[:6]}", is_local=True, is_active=True, is_locked=False,
             password_hash=hash_password(password))
    db.add(u)
    await db.flush()
    db.add(UserRole(user_id=u.id, role_name=role))
    await db.commit()
    return u


async def _password_login(web, username, password=EXAMPLE_PW):
    page = await web.get("/login")
    csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
    return await web.post("/auth/login", data={"username": username, "password": password, "_csrf": csrf})


@pytest.mark.asyncio
async def test_email_link_survives_password_sign_in(web, db):
    u = await _local_user(db, "cyber")
    r = await web.get("/vulns/abc123?tab=devices")
    assert r.status_code == 302 and r.headers["location"] == "/login?next=%2Fvulns%2Fabc123%3Ftab%3Ddevices"
    await web.get(r.headers["location"])
    r = await _password_login(web, u.username)
    assert r.status_code == 302 and r.headers["location"] == "/vulns/abc123?tab=devices"


@pytest.mark.asyncio
async def test_offsite_next_is_ignored(web, db):
    u = await _local_user(db, "cyber")
    await web.get("/login?next=//evil.example/steal")
    r = await _password_login(web, u.username)
    assert r.headers["location"] == "/"


@pytest.mark.asyncio
async def test_no_access_role_gets_the_message_and_no_session(web, db):
    u = await _local_user(db, "no_access")
    r = await _password_login(web, u.username)
    assert r.status_code == 200 and "don't have access to CTEM yet" in html.unescape(r.text)
    assert (await web.get("/")).status_code == 302  # still signed out


# ── admin wizard API ──────────────────────────────────────────────────────────

GOOD = {"provider": "okta", "fields": {"domain": "acme.okta.com", "auth_server": "org"}, "client_id": CLIENT,
        "client_secret": "s3cret-example-only", "default_role": "no_access", "mode": "both", "enabled": True,
        "no_access_message": "Ask the ACME security desk for CTEM access."}


@pytest.mark.asyncio
async def test_wizard_api_validates_and_never_returns_the_secret(client_admin, client_cyber, db):
    from sqlalchemy import select

    from api.models.settings import AppSetting
    assert (await client_cyber.get("/api/v1/admin/sso")).status_code == 403
    for bad in ({**GOOD, "provider": "nope"}, {**GOOD, "fields": {"domain": "https://bad host/"}},
                {**GOOD, "default_role": "admin"}, {**GOOD, "default_role": "made_up"},
                {**GOOD, "provider": "entra", "fields": {"tenant_id": "acme.onmicrosoft.com"}}):
        assert (await client_admin.put("/api/v1/admin/sso", json=bad)).status_code == 400
    assert (await client_admin.put("/api/v1/admin/sso", json=GOOD)).status_code == 200
    got = (await client_admin.get("/api/v1/admin/sso")).json()
    assert "client_secret" not in got["config"] and got["config"]["client_secret_set"] is True
    assert got["redirect_uri"].endswith("/auth/callback")
    assert {p["key"] for p in got["providers"]} == {"okta", "auth0", "ping", "entra"}
    assert any("/auth/callback" in s for p in got["providers"] for s in p["steps"])
    row = (await db.execute(select(AppSetting).where(AppSetting.key == "sso.oidc"))).scalar_one()
    assert "s3cret" not in row.value
    keep = {**GOOD, "client_secret": "__KEEP__", "default_role": "read_only"}
    assert (await client_admin.put("/api/v1/admin/sso", json=keep)).status_code == 200


@pytest.mark.parametrize("provider,fields,issuer", [
    ("okta", {"domain": "acme.okta.com", "auth_server": "default"}, "https://acme.okta.com/oauth2/default"),
    ("auth0", {"domain": "acme.us.auth0.com"}, "https://acme.us.auth0.com/"),
    ("ping", {"region": "eu", "environment_id": "11111111-2222-3333-4444-555555555555"},
     "https://auth.pingone.eu/11111111-2222-3333-4444-555555555555/as"),
    ("entra", {"tenant_id": "11111111-2222-3333-4444-555555555555"},
     "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"),
])
def test_issuers(provider, fields, issuer):
    from api.auth.sso_providers import issuer_for
    assert issuer_for(provider, fields) == issuer


# ── full OIDC round trip against a fake IdP ───────────────────────────────────

def _idp(nonce_box, key=KEY, issuer=ISSUER, token_issuer=ISSUER, sub="00u-alice"):
    pub = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True) | {"kid": "k1", "use": "sig", "alg": "RS256"}

    def handle(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": issuer, "authorization_endpoint": f"{ISSUER}/oauth2/v1/authorize",
                                             "token_endpoint": f"{ISSUER}/oauth2/v1/token", "jwks_uri": f"{ISSUER}/oauth2/v1/keys",
                                             "code_challenge_methods_supported": ["S256"]})
        if path == "/oauth2/v1/keys":
            return httpx.Response(200, json={"keys": [pub]})
        if path == "/oauth2/v1/token":
            now = int(time.time())
            claims = {"iss": token_issuer, "aud": CLIENT, "sub": sub, "iat": now, "exp": now + 300,
                      "nonce": nonce_box[0], "email": "alice@acme.example", "name": "Alice Example",
                      "preferred_username": "alice@acme.example"}
            return httpx.Response(200, json={"id_token": jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"}),
                                             "access_token": "at"})
        return httpx.Response(404)
    return lambda **_kw: httpx.AsyncClient(transport=httpx.MockTransport(handle))


async def _sso_round_trip(web, monkeypatch, client_admin, nonce_box, **idp):
    from api.auth import oidc
    await client_admin.put("/api/v1/admin/sso", json=GOOD)
    monkeypatch.setattr(oidc, "safe_client", _idp(nonce_box, **idp))
    r = await web.get("/auth/sso")
    assert r.status_code == 302 and r.headers["location"].startswith(f"{ISSUER}/oauth2/v1/authorize?")
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["redirect_uri"] == ["https://ctem.acme.example/auth/callback"]
    nonce_box[0] = q["nonce"][0]
    return await web.get(f"/auth/callback?code=abc&state={q['state'][0]}")


@pytest.mark.asyncio
async def test_new_sso_person_lands_on_no_access_then_pinned_role_works(web, db, monkeypatch, client_admin):
    from sqlalchemy import select

    from api.models.user import User, UserRole
    box = [None]
    sub = f"00u-{uuid.uuid4().hex[:8]}"
    await web.get("/login?next=%2Fgrc")
    r = await _sso_round_trip(web, monkeypatch, client_admin, box, sub=sub)
    assert r.status_code == 200 and "Ask the ACME security desk" in r.text
    user = (await db.execute(select(User).where(User.oidc_sub == sub))).scalar_one()
    roles = list((await db.execute(select(UserRole.role_name).where(UserRole.user_id == user.id))).scalars())
    assert roles == ["no_access"]
    # Admin pins a real role; the next sign-in goes straight to the page they wanted
    await db.execute(UserRole.__table__.delete().where(UserRole.user_id == user.id))
    db.add(UserRole(user_id=user.id, role_name="cyber"))
    await db.commit()
    await web.get("/login?next=%2Fgrc")
    r = await _sso_round_trip(web, monkeypatch, client_admin, box, sub=sub)
    assert r.status_code == 302 and r.headers["location"] == "/grc"
    roles = list((await db.execute(select(UserRole.role_name).where(UserRole.user_id == user.id))).scalars())
    assert roles == ["cyber"]  # sign-in never touches pinned roles


@pytest.mark.asyncio
async def test_forged_token_and_wrong_issuer_are_rejected(web, monkeypatch, client_admin):
    box = [None]
    r = await _sso_round_trip(web, monkeypatch, client_admin, box, key=ROGUE)
    assert r.status_code == 200 and "didn't verify" in html.unescape(r.text)
    r = await _sso_round_trip(web, monkeypatch, client_admin, box, token_issuer="https://evil.example")
    assert r.status_code == 200 and "didn't verify" in html.unescape(r.text)


@pytest.mark.asyncio
async def test_wizard_test_reports_discovery_problems(client_admin, monkeypatch):
    from api.auth import oidc
    monkeypatch.setattr(oidc, "safe_client", _idp([None], issuer="https://someone-else.example"))
    d = (await client_admin.post("/api/v1/admin/sso/test", json=GOOD)).json()
    assert d["ok"] is False and "issuer mismatch" in d["checks"][-1]["detail"]
    monkeypatch.setattr(oidc, "safe_client", _idp([None]))
    d = (await client_admin.post("/api/v1/admin/sso/test", json=GOOD)).json()
    assert d["ok"] is True and any(c["name"] == "Signing keys" and c["ok"] for c in d["checks"])


@pytest.mark.asyncio
async def test_env_auth_mode_wins(db, monkeypatch, client_admin):
    from api.auth import sso_config
    await client_admin.put("/api/v1/admin/sso", json={**GOOD, "mode": "oidc_only"})
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.setenv("AUTH_MODE", "local_only")
    assert (await sso_config.effective(db))[0] == "local_only"
    monkeypatch.delenv("AUTH_MODE")
    mode, cfg = await sso_config.effective(db)
    assert mode == "oidc_only" and cfg.issuer == ISSUER


@pytest.mark.asyncio
async def test_sso_asks_for_the_authenticator_enrolled_in_ctem(web, db, monkeypatch, client_admin):
    """CTE-034: an SSO account with a CTEM authenticator gets the code step after the IdP, not a session."""
    import re

    import pyotp
    from fastapi import HTTPException
    from sqlalchemy import select

    from api.auth import local
    from api.core.encryption import decrypt, encrypt
    from api.models.user import User, UserRole

    async def verify(username, code, stored, *rest):   # the real code check, minus Redis
        if not pyotp.TOTP(decrypt(stored)).verify(code, valid_window=1):
            raise HTTPException(401, detail="Invalid code")
    monkeypatch.setattr(local, "verify_totp", verify)
    box, sub, secret = [None], f"00u-{uuid.uuid4().hex[:8]}", pyotp.random_base32()
    await _sso_round_trip(web, monkeypatch, client_admin, box, sub=sub)
    user = (await db.execute(select(User).where(User.oidc_sub == sub))).scalar_one()
    await db.execute(UserRole.__table__.delete().where(UserRole.user_id == user.id))
    db.add(UserRole(user_id=user.id, role_name="cyber"))
    user.totp_enabled, user.totp_secret = True, encrypt(secret)
    await db.commit()
    r = await _sso_round_trip(web, monkeypatch, client_admin, box, sub=sub)
    assert r.status_code == 200 and 'action="/auth/totp"' in r.text   # the code step, not a session
    assert not await _signed_in(web)
    token = re.search(r'name="_csrf" value="([^"]*)"', r.text).group(1)
    bad = await web.post("/auth/totp", data={"totp_code": "000000", "_csrf": token})
    assert bad.status_code == 200 and not await _signed_in(web)
    token = re.search(r'name="_csrf" value="([^"]*)"', bad.text).group(1)
    ok = await web.post("/auth/totp", data={"totp_code": pyotp.TOTP(secret).now(), "_csrf": token})
    assert ok.status_code in (302, 303) and await _signed_in(web)


async def _signed_in(web) -> bool:
    return (await web.get("/api/v1/auth/totp/status", follow_redirects=False)).status_code == 200
