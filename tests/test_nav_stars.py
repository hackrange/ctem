"""Sidebar stars: saved with the person's preferences, page paths only."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_starred_nav_saves_and_rejects_anything_but_paths(client_it_user):
    r = await client_it_user.patch("/api/v1/profile/prefs", json={"starred_nav": ["/vulns", "/devices"]})
    assert r.status_code == 200 and r.json()["prefs"]["starred_nav"] == ["/vulns", "/devices"]
    assert (await client_it_user.get("/api/v1/profile/prefs")).json()["prefs"]["starred_nav"] == ["/vulns", "/devices"]
    for bad in (["javascript:alert(1)"], ["https://evil.example/"], ["/x\"><script>"], ["//evil.example"], ["/a"] * 41, "nope"):
        assert (await client_it_user.patch("/api/v1/profile/prefs", json={"starred_nav": bad})).status_code == 422, bad
