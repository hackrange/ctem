"""Tests for IP-bound API token system."""
from __future__ import annotations

import hashlib
import secrets

import pytest
import pytest_asyncio

from api.auth.middleware import _ip_allowed


# ── _ip_allowed unit tests ─────────────────────────────────────────────────────

def test_exact_ip_match():
    assert _ip_allowed("192.168.1.10", ["192.168.1.10"]) is True


def test_exact_ip_no_match():
    assert _ip_allowed("192.168.1.11", ["192.168.1.10"]) is False


def test_cidr_match():
    assert _ip_allowed("10.0.1.5", ["10.0.0.0/8"]) is True


def test_cidr_no_match():
    assert _ip_allowed("172.16.0.1", ["10.0.0.0/8"]) is False


def test_empty_allowed_list_denies_all():
    assert _ip_allowed("203.0.113.4", []) is False


def test_multiple_entries_first_matches():
    assert _ip_allowed("203.0.113.4", ["198.51.100.9", "203.0.113.4"]) is True


def test_invalid_caller_ip():
    assert _ip_allowed("not-an-ip", ["203.0.113.4"]) is False


def test_invalid_entry_skipped():
    # Bad entry in list should be skipped, not crash
    assert _ip_allowed("203.0.113.4", ["not-valid", "203.0.113.4"]) is True


def test_ipv6_exact():
    assert _ip_allowed("::1", ["::1"]) is True


def test_ipv6_cidr():
    assert _ip_allowed("2001:db8::1", ["2001:db8::/32"]) is True


# ── Token API integration tests ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_token_defaults_to_caller_ip(client, admin_user, db):
    # Authenticate as admin_user by injecting the dependency
    from api.auth.middleware import get_current_user
    from api.main import create_app

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: admin_user

    from httpx import ASGITransport, AsyncClient
    from api.core.db import get_session

    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers={"Origin": "http://test"}) as ac:
        resp = await ac.post("/api/v1/tokens", json={"name": "test-token"})

    assert resp.status_code == 201
    data = resp.json()
    assert "token" in data
    assert len(data["token"]) == 64
    assert data["allowed_ips"] == ["127.0.0.1"]  # httpx ASGITransport default IP


@pytest.mark.asyncio
async def test_create_token_with_explicit_ips(client, admin_user, db):
    from api.auth.middleware import get_current_user
    from api.main import create_app
    from api.core.db import get_session
    from httpx import ASGITransport, AsyncClient

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: admin_user
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers={"Origin": "http://test"}) as ac:
        resp = await ac.post("/api/v1/tokens", json={
            "name": "acme-integration",
            "allowed_ips": ["10.0.0.1", "10.0.0.2"],
        })

    assert resp.status_code == 201
    assert resp.json()["allowed_ips"] == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.asyncio
async def test_create_token_invalid_ip_rejected(client, admin_user, db):
    from api.auth.middleware import get_current_user
    from api.main import create_app
    from api.core.db import get_session
    from httpx import ASGITransport, AsyncClient

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: admin_user
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers={"Origin": "http://test"}) as ac:
        resp = await ac.post("/api/v1/tokens", json={
            "name": "bad-token",
            "allowed_ips": ["not-an-ip-address"],
        })

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_tokens(admin_user, db, api_token_for):
    from api.auth.middleware import get_current_user
    from api.main import create_app
    from api.core.db import get_session
    from httpx import ASGITransport, AsyncClient

    plain, _ = await api_token_for(admin_user)

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: admin_user
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers={"Origin": "http://test"}) as ac:
        resp = await ac.get("/api/v1/tokens")

    assert resp.status_code == 200
    tokens = resp.json()["tokens"]
    assert len(tokens) >= 1
    # Token value must never appear in list response
    assert all("token" not in t for t in tokens)
