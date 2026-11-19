"""Tests for threat alerts endpoint -- cyber/admin only."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_threat_alerts_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/threat/alerts")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_threat_alerts_read_only_denied(client_read_only):
    r = await client_read_only.get("/api/v1/threat/alerts")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_threat_alerts_cyber_allowed(client_cyber):
    r = await client_cyber.get("/api/v1/threat/alerts")
    assert r.status_code == 200
    d = r.json()
    assert "alerts" in d
    assert isinstance(d["alerts"], list)
    assert "total" in d


@pytest.mark.asyncio
async def test_threat_alerts_severity_filter(client_cyber):
    r = await client_cyber.get("/api/v1/threat/alerts?severity=high")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_threat_alerts_source_filter(client_cyber):
    r = await client_cyber.get("/api/v1/threat/alerts?source=crowdstrike")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_threat_alerts_limit_cap(client_cyber):
    # Over the 200-row cap should 422
    r = await client_cyber.get("/api/v1/threat/alerts?limit=9999")
    assert r.status_code == 422
