"""Tests for identity risk routes -- BOLA prevention, auth enforcement, response shape."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from api.models.identity import (
    IdentityRiskScore,
    IdentityThreat,
    ItdrAlertStatus,
    ItdrThreatType,
    PostureFinding,
    SaasAppRecord,
)


@pytest.mark.asyncio
async def test_itdr_threats_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/identity/threats")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_itdr_threats_read_only_role_denied(client_read_only):
    """read_only role must NOT access identity -- require_cyber_or_admin."""
    r = await client_read_only.get("/api/v1/identity/threats")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_itdr_threats_empty(client_cyber):
    r = await client_cyber.get("/api/v1/identity/threats")
    assert r.status_code == 200
    body = r.json()
    assert "threats" in body
    assert isinstance(body["threats"], list)
    assert "total" in body


@pytest.mark.asyncio
async def test_itdr_threats_summary(client_cyber):
    r = await client_cyber.get("/api/v1/identity/threats/summary")
    assert r.status_code == 200
    body = r.json()
    assert "by_severity" in body
    assert "total_active" in body


@pytest.mark.asyncio
async def test_posture_empty(client_cyber):
    r = await client_cyber.get("/api/v1/identity/posture")
    assert r.status_code == 200
    assert "findings" in r.json()


@pytest.mark.asyncio
async def test_saas_apps_filter(client_cyber):
    for app_type in ("all", "shadow_saas", "shadow_ai", "ai_agent"):
        r = await client_cyber.get(f"/api/v1/identity/saas-apps?app_type={app_type}")
        assert r.status_code == 200, f"app_type={app_type} returned {r.status_code}"
        assert "apps" in r.json()


@pytest.mark.asyncio
async def test_saas_apps_summary(client_cyber):
    r = await client_cyber.get("/api/v1/identity/saas-apps/summary")
    assert r.status_code == 200
    body = r.json()
    for key in ("total_apps", "shadow_saas", "shadow_ai", "ai_agents", "unsanctioned"):
        assert key in body


@pytest.mark.asyncio
async def test_identity_scores_empty(client_cyber):
    r = await client_cyber.get("/api/v1/identity/scores")
    assert r.status_code == 200
    body = r.json()
    assert "scores" in body
    assert "total" in body


@pytest.mark.asyncio
async def test_itdr_severity_filter(client_cyber, db_session):
    """Severity filter must only return matching records."""
    threat = IdentityThreat(
        source="grip",
        external_id="test-001",
        threat_type=ItdrThreatType.impossible_travel,
        severity="critical",
        status=ItdrAlertStatus.active,
        title="Test impossible travel",
        detected_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )
    db_session.add(threat)
    await db_session.commit()

    r_all = await client_cyber.get("/api/v1/identity/threats?severity=critical")
    assert r_all.status_code == 200
    assert all(t["severity"] == "critical" for t in r_all.json()["threats"])

    r_low = await client_cyber.get("/api/v1/identity/threats?severity=low")
    assert r_low.status_code == 200
    low_ids = {t["id"] for t in r_low.json()["threats"]}
    assert str(threat.id) not in low_ids


@pytest.mark.asyncio
async def test_attack_paths_requires_cyber(client_no_auth):
    r = await client_no_auth.get("/api/v1/attack-paths/chains")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_attack_paths_empty(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/chains")
    assert r.status_code == 200
    body = r.json()
    assert "chains" in body
    assert "total" in body


@pytest.mark.asyncio
async def test_attack_paths_pivot_points(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/pivot-points")
    assert r.status_code == 200
    assert "pivot_points" in r.json()


@pytest.mark.asyncio
async def test_attack_paths_summary(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/summary")
    assert r.status_code == 200
    body = r.json()
    assert "total_reachable_findings" in body


@pytest.mark.asyncio
async def test_page_access_identity_requires_tag_or_role(client_it_user):
    """it_user without identity tag gets 404 on /identity."""
    r = await client_it_user.get("/identity", follow_redirects=False)
    assert r.status_code == 404
