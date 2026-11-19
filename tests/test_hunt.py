"""Tests for hunt query endpoints -- cyber/admin only."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_hunt_query_requires_auth(client_no_auth):
    r = await client_no_auth.post("/api/v1/hunt/query", json={"query": "test"})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_hunt_query_read_only_denied(client_read_only):
    r = await client_read_only.post("/api/v1/hunt/query", json={"query": "test"})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_hunt_query_cyber_allowed(client_cyber):
    r = await client_cyber.post("/api/v1/hunt/query", json={"query": "login failures on server001"})
    assert r.status_code == 200
    d = r.json()
    # Either AI or keyword mode depending on settings
    assert d["mode"] in ("ai", "keyword")
    assert "telemetry_sources" in d


@pytest.mark.asyncio
async def test_hunt_query_with_asset_hint(client_cyber):
    r = await client_cyber.post("/api/v1/hunt/query",
                                 json={"query": "unexpected outbound", "asset_hint": "server001"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_hunt_query_empty_query_rejected(client_cyber):
    r = await client_cyber.post("/api/v1/hunt/query", json={"query": ""})
    # Empty query should 422 (Pydantic validation) or 400
    assert r.status_code in (400, 422)


@pytest.mark.asyncio
async def test_hunt_result_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/hunt/result/fake-task-id")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_hunt_result_nonexistent_task(client_cyber):
    pytest.importorskip("celery")
    r = await client_cyber.get("/api/v1/hunt/result/does-not-exist-task-id")
    # 404 or returns pending status -- either is fine
    assert r.status_code in (200, 404)
