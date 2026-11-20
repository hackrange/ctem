"""Shippers live under Integrations and SSO under Admin; the old URLs still work."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_tabs_replace_sidebar_entries(client_admin):
    admin = (await client_admin.get("/admin")).text
    assert 'href="/settings/sso"' in admin and 'data-tab="rules"' in admin and 'id="pane-rules"' in admin
    sso = (await client_admin.get("/settings/sso")).text
    assert 'aria-current="page">Single sign-on' in sso and 'href="/admin#roles"' in sso
    ship = (await client_admin.get("/settings/shippers")).text
    integ = (await client_admin.get("/settings/integrations")).text
    assert 'aria-current="page">Shippers' in ship and 'aria-current="page">Integrations' in integ
    nav = admin.split('<main', 1)[0]
    assert 'href="/settings/sso" class="sidebar__link' not in nav and 'href="/settings/shippers" class="sidebar__link' not in nav
