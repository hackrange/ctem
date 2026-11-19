"""Tests for auth flow: CSRF, lockout, session."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_login_page_returns_200(client):
    resp = await client.get("/login")
    assert resp.status_code in (200, 302)  # 302 if oidc_only mode


@pytest.mark.asyncio
async def test_login_without_csrf_returns_403(client):
    resp = await client.post("/auth/login", data={
        "username": "anyone",
        "password": "whatever",
        # no _csrf field
    })
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_login_with_wrong_csrf_returns_403(client):
    resp = await client.post("/auth/login", data={
        "username": "anyone",
        "password": "whatever",
        "_csrf": "clearly:invalid",
    })
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_health_endpoint(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_api_requires_auth(client):
    resp = await client.get("/api/v1/devices")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_rejects_bearer_with_wrong_ip(admin_user, db, api_token_for):
    """Token from IP 1.2.3.4 must be rejected when caller is 127.0.0.1."""
    from api.main import create_app
    from api.core.db import get_session
    from httpx import ASGITransport, AsyncClient

    plain, _ = await api_token_for(admin_user, allowed_ip="1.2.3.4")

    app = create_app()
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            "/api/v1/devices",
            headers={"Authorization": f"Bearer {plain}"},
        )

    # testclient IP is "testclient", not "1.2.3.4" -- should reject
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_accepts_valid_ip_bound_token(admin_user, db, api_token_for):
    """Token bound to testclient IP must work from that IP."""
    from api.main import create_app
    from api.core.db import get_session
    from httpx import ASGITransport, AsyncClient

    # httpx test client reports IP as "testclient"
    plain, _ = await api_token_for(admin_user, allowed_ip="testclient")

    app = create_app()
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            "/api/v1/devices",
            headers={"Authorization": f"Bearer {plain}"},
        )

    assert resp.status_code == 200
