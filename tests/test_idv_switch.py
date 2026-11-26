"""Discovered Users only for the roles its data allows; Persona's "Enable IDV approval" hides the IDV page and link
and refuses decisions, while the IDV badges stay."""
from __future__ import annotations

import pytest
from sqlalchemy import delete


def test_discovered_users_page_matches_its_data():
    from api.core.page_access import can_access_page
    assert can_access_page("/users", ["cyber"], []) and can_access_page("/users", ["admin"], [])
    for role in ("it_user", "read_only", "idv_validation"):
        assert not can_access_page("/users", [role], ["users", "devices", "identity"]), role


@pytest.mark.asyncio
async def test_idv_approval_switch(db, client_idv_approver, client_cyber):
    from api.models.integration import IntegrationConfig, Vendor
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.persona))
    cfg = IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "w" * 36})
    db.add(cfg)
    await db.commit()
    try:
        on = await client_cyber.get("/idv")
        assert on.status_code == 200 and 'href="/idv"' in on.text      # saved before the setting existed: on
        cfg.config = {**cfg.config, "idv_page": False}
        await db.commit()
        assert (await client_cyber.get("/idv")).status_code == 404
        assert 'href="/idv"' not in (await client_cyber.get("/vulns")).text   # no sidebar link
        r = await client_idv_approver.post("/api/v1/idv/people/00000000-0000-0000-0000-000000000000/revoke",
                                           json={"reason": "other", "note": "test note"})
        assert r.status_code == 409 and "turned off" in r.json()["detail"]
    finally:
        await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cfg.id))
        await db.commit()
