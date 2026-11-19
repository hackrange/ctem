"""Cross-site write protection."""


async def test_cross_site_write_blocked(client_admin):
    r = await client_admin.post("/api/v1/tokens", json={"name": "evil"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


async def test_write_without_origin_blocked(client_admin):
    client_admin.headers.pop("Origin", None)
    r = await client_admin.post("/api/v1/tokens", json={"name": "evil"})
    assert r.status_code == 403


async def test_same_origin_write_allowed(client_admin):
    r = await client_admin.post("/api/v1/tokens", json={"name": "fine"})
    assert r.status_code != 403


async def test_bearer_write_skips_origin_check(client_admin):
    client_admin.headers.pop("Origin", None)
    r = await client_admin.post("/api/v1/tokens", json={"name": "api"}, headers={"Authorization": "Bearer x"})
    assert r.status_code != 403
