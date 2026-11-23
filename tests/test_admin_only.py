"""Only admins do admin things: Admin and Settings pages, API tokens, API docs and integrations stay shut to cyber."""
from __future__ import annotations

import pytest

ADMIN_PAGES = ("/admin", "/admin/maintenance", "/settings/integrations", "/settings/tokens", "/settings/sso",
               "/settings/shippers")


@pytest.mark.asyncio
async def test_cyber_gets_no_admin_pages_or_sidebar_links(client_cyber, client_admin):
    for page in ADMIN_PAGES:
        assert (await client_cyber.get(page, headers={"Accept": "text/html"})).status_code == 404, page
        assert (await client_admin.get(page, headers={"Accept": "text/html"})).status_code == 200, page
    nav = (await client_cyber.get("/vulns", headers={"Accept": "text/html"})).text.split("<main", 1)[0]
    for link in ('href="/admin"', 'href="/settings/integrations"', 'href="/settings/tokens"', 'href="/api/docs"'):
        assert link not in nav
    admin_nav = (await client_admin.get("/vulns", headers={"Accept": "text/html"})).text.split("<main", 1)[0]
    assert all(link in admin_nav for link in ('href="/admin"', 'href="/settings/tokens"', 'href="/api/docs"'))


def test_a_page_tag_named_admin_opens_nothing():
    from api.core.page_access import can_access_page
    assert not can_access_page("/admin", ["it_user"], ["admin"])
    assert not can_access_page("/settings/tokens", ["cyber"], ["admin"])
    assert can_access_page("/admin", ["admin"], [])
    assert can_access_page("/threat", ["cyber"], [])   # analyst pages unchanged


@pytest.mark.asyncio
async def test_cyber_cannot_use_admin_apis(client_cyber):
    for method, path in (("GET", "/api/v1/tokens"), ("POST", "/api/v1/tokens"), ("GET", "/api/v1/integrations"),
                         ("GET", "/api/v1/integrations/vendors"), ("GET", "/api/docs"), ("GET", "/api/openapi.json"),
                         ("GET", "/api/v1/admin/maintenance")):
        r = await client_cyber.request(method, path, json={"name": "x-token"} if method == "POST" else None)
        assert r.status_code == 403, (method, path, r.status_code)


@pytest.mark.asyncio
async def test_admin_mints_a_token_for_another_account(db, client_admin, client, it_user):
    from api.models.settings import AuditLog
    from sqlalchemy import select
    r = await client_admin.post("/api/v1/tokens", json={"name": "inventory script", "owner_username": it_user.username,
                                                         "allowed_ips": ["127.0.0.1"]})
    assert r.status_code == 201, r.text
    # the token works and carries that account's own (non-admin) permissions
    auth = {"Authorization": f"Bearer {r.json()['token']}"}
    assert (await client.get("/api/v1/tokens", headers=auth)).status_code == 403
    assert (await client.get("/api/v1/profile/prefs", headers=auth)).status_code == 200
    rows = (await db.execute(select(AuditLog).where(AuditLog.action == "api_token_created"))).scalars().all()
    assert any(it_user.username in (a.detail or "") for a in rows)
    bad = await client_admin.post("/api/v1/tokens", json={"name": "nobody", "owner_username": "no-such-user"})
    assert bad.status_code == 400
