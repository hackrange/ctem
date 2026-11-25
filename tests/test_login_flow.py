"""Browser login flow and threat alert feed regressions."""
import json
import re

from api.models.settings import AppSetting


def _csrf(html: str) -> str:
    return re.search(r'name="_csrf" value="([^"]*)"', html).group(1)


async def test_typo_then_retry_still_has_csrf(client):
    client.base_url = "https://test"  # session cookie is Secure
    page = await client.get("/login")
    r = await client.post("/auth/login", data={"username": "nobody", "password": "nope", "_csrf": _csrf(page.text)})
    # 200, not 4xx: the upstream LB replaces 4xx bodies and would hide the form
    assert r.status_code == 200
    assert "Sign-in failed" in r.text
    token = _csrf(r.text)
    assert token
    r2 = await client.post("/auth/login", data={"username": "nobody", "password": "nope", "_csrf": token})
    assert r2.status_code == 200  # CSRF accepted; credentials still wrong


async def test_login_without_csrf_rejected(client):
    r = await client.post("/auth/login", data={"username": "x", "password": "y"})
    assert r.status_code == 200 and "form expired" in r.text


async def test_a_double_submitted_sign_in_lands_signed_in_not_on_a_403(client, db, monkeypatch):
    """The first submit signs in and starts a fresh session, so the second one's token can't match. It mustn't be
    processed, and the person, who is signed in, goes on to where they were headed (on this site only)."""
    import uuid

    from api.core.config import get_settings
    monkeypatch.setattr(get_settings(), "mfa_required", False)   # a password-only sign-in, whatever .env says
    from api.auth.local import hash_password
    from api.models.user import User, UserRole
    name = f"twice_{uuid.uuid4().hex[:6]}"
    u = User(username=name, is_local=True, is_active=True, password_hash=hash_password("correct horse battery"))
    db.add(u)
    await db.flush()
    db.add(UserRole(user_id=u.id, role_name="cyber"))
    await db.commit()
    client.base_url = "https://test"
    page = await client.get("/login?next=/threat")
    form = {"username": name, "password": "correct horse battery", "_csrf": _csrf(page.text)}
    first = await client.post("/auth/login", data=form)
    assert first.status_code == 302 and first.headers["location"] == "/threat"
    again = await client.post("/auth/login", data=form, headers={"Referer": "https://test/login?next=/threat"})
    assert again.status_code == 303 and again.headers["location"] == "/threat"
    for evil in ("//evil.example/x", "https://evil.example/", "/\\evil.example"):
        r = await client.post("/auth/login", data=form, headers={"Referer": f"https://test/login?next={evil}"})
        assert r.status_code == 303 and r.headers["location"] == "/", evil
    # signed out, the same stale form only shows the form again: nothing it carries is used
    client.cookies.clear()
    r = await client.post("/auth/login", data=form)
    assert r.status_code == 200 and "form expired" in r.text
    home = await client.get("/", follow_redirects=False)   # not signed in: refused, or sent to sign in
    assert home.status_code == 401 or home.headers.get("location", "").startswith("/login")


async def test_a_stale_totp_form_never_checks_the_code(client, monkeypatch):
    from api.auth import local
    checked = []

    async def spy(*a, **k):
        checked.append(1)
    monkeypatch.setattr(local, "verify_totp", spy)
    client.base_url = "https://test"
    await client.get("/login")
    r = await client.post("/auth/totp", data={"totp_code": "123456", "_csrf": "stale:token"})
    assert r.status_code == 200 and "form expired" in r.text and not checked


async def test_the_sign_in_button_greys_out_with_a_same_origin_script_only(client):
    client.base_url = "https://test"
    page = await client.get("/login")
    csp = page.headers["content-security-policy"]
    assert "script-src 'self';" in csp and "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "js/login_submit.js" in page.text and "<script>" not in page.text


async def test_totp_step_without_pending_login(client):
    client.base_url = "https://test"
    page = await client.get("/login")
    r = await client.post("/auth/totp", data={"totp_code": "123456", "_csrf": _csrf(page.text)})
    assert "Sign-in expired" in r.text


async def test_mfa_required_enrolls_on_first_login(client, db, monkeypatch):
    import uuid
    import pyotp
    from sqlalchemy import select
    from api.auth.local import hash_password
    from api.core.config import get_settings
    from api.models.user import User, UserRole

    monkeypatch.setattr(get_settings(), "mfa_required", True)
    name = f"enroll_{uuid.uuid4().hex[:6]}"
    u = User(username=name, is_local=True, is_active=True, password_hash=hash_password("correct horse battery"))
    db.add(u)
    await db.flush()
    db.add(UserRole(user_id=u.id, role_name="cyber"))  # a role-less account stops at the no-access message
    await db.commit()

    client.base_url = "https://test"
    page = await client.get("/login")
    r = await client.post("/auth/login", data={"username": name, "password": "correct horse battery", "_csrf": _csrf(page.text)})
    assert 'action="/auth/totp"' in r.text and "data:image/png;base64," in r.text
    secret = re.search(r'monospace[^>]*>([A-Z2-7]{16,})<', r.text).group(1)

    bad = await client.post("/auth/totp", data={"totp_code": "000000", "_csrf": _csrf(r.text)})
    assert "match. Try the next one" in bad.text and "data:image/png;base64," in bad.text
    ok = await client.post("/auth/totp", data={"totp_code": pyotp.TOTP(secret).now(), "_csrf": _csrf(bad.text)})
    assert ok.status_code == 302 and ok.headers["location"] == "/"

    db.expire_all()
    user = (await db.execute(select(User).where(User.username == name))).scalar_one()
    assert user.totp_enabled is True


async def test_threat_alerts_include_connector_cache(client_cyber, db):
    db.add(AppSetting(key="threat_alert_splunk_abc", value=json.dumps({"source": "splunk", "severity": "high"})))
    await db.commit()
    r = await client_cyber.get("/api/v1/threat/alerts?source=splunk")
    assert r.status_code == 200
    assert r.json()["total"] >= 1
