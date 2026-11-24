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
