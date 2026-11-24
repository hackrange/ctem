"""Grip's API lives under /public on the tenant; the bare tenant answers with the web app's HTML."""
from __future__ import annotations

import pytest


@pytest.mark.parametrize("entered", ["https://acme.dep.grip.security/public/saas", "https://acme.dep.grip.security/public/saas/",
                                     "https://acme.dep.grip.security/public", "https://acme.dep.grip.security"])
def test_every_endpoint_is_under_public_whatever_url_was_entered(entered):
    import api.integrations.grip  # noqa: F401 -- registers the connector
    from api.integrations.base import get_connector
    c = get_connector("grip", {"base_url": entered, "api_key": "k"})
    assert c._root_url() == "https://acme.dep.grip.security/public"
    assert (c._root_url() + "/threats").endswith("/public/threats") and c._saas_url() == "https://acme.dep.grip.security/public/saas"


def test_only_ai_native_and_copilot_apps_count_as_ai_apps():
    from api.integrations.grip import is_ai_app
    assert is_ai_app("AI-Native App") and is_ai_app("AI Copilot Experience")
    assert not any(is_ai_app(x) for x in ("No AI", "AI Features/Add-on", None, "", 3))


@pytest.mark.asyncio
async def test_a_sync_only_reads_and_maps_what_grip_returns(db, monkeypatch):
    """Shapes as the live API returns them (verified 2026-11-24): plain lists, access-token header, GET only."""
    import httpx

    import api.integrations.grip as grip
    from api.integrations.base import get_connector
    calls = []
    data = {
        "/public/threats": [{"alertId": "A-1", "alertName": "Impossible travel", "alertSeverity": "High", "alertType": "impossible_travel",
                             "status": "Open", "createdAt": "2026-11-20T10:00:00Z", "relatedIdentityMail": "jdoe@acme.example",
                             "relatedEntityType": "user", "relatedEntityId": "u1"}],
        "/public/posture-checks": [{"uuid": "p1", "postureCheckId": "MFA_ENFORCED", "severity": "High", "description": "MFA not enforced",
                                    "findingsCount": 3, "status": "Failed", "updatedAt": "2026-11-20T10:00:00Z"}],
        "/public/saas": [{"id": "s1", "name": "ChatThing", "gripData": {"aiDepth": {"level": "AI-Native App"}, "riskScore": 70}},
                         {"id": "s2", "name": "Notes", "gripData": {"aiDepth": {"level": "AI Features/Add-on"}, "riskScore": 10}}],
        "/public/ai-agents": [{"id": "g1", "name": "Helper", "score": 55, "ownerEmail": "jdoe@acme.example"}],
        "/public/users": [{"id": "u1", "mail": "jdoe@acme.example", "gripData": {"numberOfSaas": 4}}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        assert request.method == "GET" and request.headers.get("access-token") == "k"
        rows = data.get(request.url.path, [])
        return httpx.Response(200, json=rows if int(request.url.params.get("offset", 0)) == 0 else [])
    monkeypatch.setattr(grip, "safe_client", lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    c = get_connector("grip", {"base_url": "https://acme.dep.grip.security", "api_key": "k"})
    assert await c.sync(db) == 6 and set(calls) == {"GET"}   # 1 threat, 1 check, 2 apps, 1 agent, 1 person
    from sqlalchemy import select

    from api.models.identity import SaasAppRecord
    apps = {r.external_id: r for r in (await db.execute(select(SaasAppRecord).where(SaasAppRecord.external_id.in_(["s1", "s2"])))).scalars()}
    assert apps["s1"].is_shadow_ai and not apps["s2"].is_shadow_ai


@pytest.mark.asyncio
async def test_extensions_desktop_ai_and_credentials_feed_identity_risk(db, monkeypatch):
    """Shapes from the live tenant and Grip's spec (2026-11-24); GET only."""
    import httpx

    import api.integrations.grip as grip
    from api.core.encryption import search_hash
    from api.integrations.base import get_connector
    from api.models.device import Device, DeviceType
    from api.models.identity import IdentityRiskScore, SaasAppRecord
    from api.models.software import SoftwareInstall
    from sqlalchemy import select
    import uuid as _uuid
    tag = _uuid.uuid4().hex[:6]
    mail = f"pat{tag}@acme.example"
    host = f"LT-{tag}"
    db.add(Device(hostname=host, device_type=DeviceType.workstation))
    await db.commit()
    bad, mid = f"ext-bad-{tag}", f"ext-mid-{tag}"
    data = {
        "/public/extensions": [{"extensionId": bad, "name": "Coupon Helper", "platform": "chrome", "riskScore": 90, "riskLevel": "High",
                                "isMalicious": True, "maliciousReason": "exfiltrates cookies", "permissions": ["cookies", "<all_urls>"],
                                "assets": [], "totalInstances": 3, "activeInstances": 2, "sanctionState": "New"},
                               {"extensionId": mid, "name": "AI Writer", "riskScore": 70, "riskLevel": "High", "isMalicious": False,
                                "assets": ["AI"], "permissions": [], "totalInstances": 1, "activeInstances": 1}],
        f"/public/extensions/{bad}": {"installations": {"total": 1, "items": [{"identityEmail": mail, "status": "enabled"}]}},
        f"/public/extensions/{mid}": {"installations": {"total": 1, "items": [{"identityEmail": mail, "status": "enabled"}]}},
        "/public/desktop-ai-apps": [{"id": "d1", "name": f"AI Browser {tag}", "category": "AI Browser"}],
        "/public/desktop-ai-apps/d1": {"installations": {"total": 1, "items": [{"deviceName": host, "version": "1.2", "platform": "macOS"}]}},
        "/public/users": [{"id": "u1", "mail": mail, "gripData": {"numberOfSaas": 2, "passwordPosture": {"leakedPasswordAccounts": 1,
                           "reusedPasswordAccounts": 2, "weakPasswordAccounts": 0}, "mfaStatusByApp": {"coveragePercentage": 40}}}],
    }
    methods = []

    def handler(request):
        methods.append(request.method)
        body = data.get(request.url.path, [])
        if isinstance(body, list) and int(request.url.params.get("offset", 0)):
            body = []
        return httpx.Response(200, json=body)
    monkeypatch.setattr(grip, "safe_client", lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await get_connector("grip", {"base_url": "https://acme.dep.grip.security", "api_key": "k"}).sync(db)
    assert set(methods) == {"GET"}
    ext = {r.external_id: r for r in (await db.execute(select(SaasAppRecord).where(SaasAppRecord.source == "grip_extension"))).scalars()}
    assert ext[bad].risk_level == "critical" and ext[bad].data_access_scopes["malicious"] and ext[mid].is_shadow_ai
    assert mail not in str(ext[bad].data_access_scopes) and ext[bad].data_access_scopes["people"]   # masked, never the address
    person = (await db.execute(select(IdentityRiskScore).where(IdentityRiskScore.user_email_hash == search_hash(mail)))).scalar_one()
    assert person.leaked_password_accounts == 1 and person.reused_password_accounts == 2 and person.mfa_coverage_pct == 40
    assert person.risky_extensions == 2 and person.credential_score == min(100, 25 + 40 + 16 + 6 + 10)
    assert person.composite_identity_score >= 0.15 * person.credential_score
    dev = (await db.execute(select(Device).where(Device.hostname == host))).scalar_one()
    assert (await db.execute(select(SoftwareInstall).where(SoftwareInstall.device_id == dev.id, SoftwareInstall.source == "grip"))).scalar_one()
