"""Tests for device endpoints -- especially BOLA/IDOR prevention."""
from __future__ import annotations

import uuid

import pytest


@pytest.mark.asyncio
async def test_device_404_for_nonexistent(admin_user, db, api_token_for):
    from api.main import create_app
    from api.core.db import get_session
    from httpx import ASGITransport, AsyncClient

    plain, _ = await api_token_for(admin_user, allowed_ip="testclient")

    app = create_app()
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/devices/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {plain}"},
        )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_device_404_not_403_for_unowned(cyber_user, admin_user, db, api_token_for):
    """
    A device that exists but isn't visible to cyber_user should return 404 not 403.
    404 prevents enumeration of valid IDs (BOLA-safe).
    """
    from api.main import create_app
    from api.core.db import get_session
    from api.models.device import Device, DeviceType
    from httpx import ASGITransport, AsyncClient

    # Create a device not tagged for cyber_user's tag scope
    device = Device(id=uuid.uuid4(), hostname="secret-host", device_type=DeviceType.server, source="test")
    db.add(device)
    await db.commit()

    # Token for cyber_user
    plain, _ = await api_token_for(cyber_user, allowed_ip="testclient")

    app = create_app()
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/devices/{device.id}",
            headers={"Authorization": f"Bearer {plain}"},
        )

    # Must be 404, never 403 (no enumeration oracle)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_device_list_returns_200(admin_user, db, api_token_for):
    from api.main import create_app
    from api.core.db import get_session
    from httpx import ASGITransport, AsyncClient

    plain, _ = await api_token_for(admin_user, allowed_ip="testclient")

    app = create_app()
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            "/api/v1/devices",
            headers={"Authorization": f"Bearer {plain}"},
        )

    assert resp.status_code == 200
    assert "devices" in resp.json()
