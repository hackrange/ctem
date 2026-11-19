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
    assert r.status_code == 403


async def test_totp_step_without_pending_login(client):
    client.base_url = "https://test"
    page = await client.get("/login")
    r = await client.post("/auth/totp", data={"totp_code": "123456", "_csrf": _csrf(page.text)})
    assert "Sign-in expired" in r.text


async def test_threat_alerts_include_connector_cache(client_cyber, db):
    db.add(AppSetting(key="threat_alert_splunk_abc", value=json.dumps({"source": "splunk", "severity": "high"})))
    await db.commit()
    r = await client_cyber.get("/api/v1/threat/alerts?source=splunk")
    assert r.status_code == 200
    assert r.json()["total"] >= 1
