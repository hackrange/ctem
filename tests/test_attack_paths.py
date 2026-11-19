"""Tests for attack paths API -- auth enforcement and response shape."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_chains_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/attack-paths/chains")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_chains_read_only_denied(client_read_only):
    r = await client_read_only.get("/api/v1/attack-paths/chains")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_chains_cyber_allowed(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/chains")
    assert r.status_code == 200
    d = r.json()
    assert "chains" in d
    assert "total" in d


@pytest.mark.asyncio
async def test_chains_kev_filter(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/chains?kev_only=true")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_chains_min_hops(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/chains?min_hops=2")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_pivot_points_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/attack-paths/pivot-points")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_pivot_points_cyber_allowed(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/pivot-points")
    assert r.status_code == 200
    d = r.json()
    assert "pivot_points" in d


@pytest.mark.asyncio
async def test_summary_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/attack-paths/summary")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_summary_shape(client_cyber):
    r = await client_cyber.get("/api/v1/attack-paths/summary")
    assert r.status_code == 200
    d = r.json()
    assert "total_reachable_findings" in d
    assert "kev_reachable" in d


@pytest.mark.asyncio
async def test_page_attack_paths_requires_auth(client_no_auth):
    r = await client_no_auth.get("/attack-paths")
    assert r.status_code in (401, 403, 404)


@pytest.mark.asyncio
async def test_page_attack_paths_it_user_denied(client_it_user):
    """it_user has no attack-paths tag so gets 404 (BOLA-safe)."""
    r = await client_it_user.get("/attack-paths")
    assert r.status_code == 404
