"""Pause integration syncing: admins only, audited; while paused nothing new syncs (scheduled, queued, Sync Now or a
shipper's upload), a timed pause ends on its own, and resuming brings everything back."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select


async def _clear(db):
    from api.core import sync_pause
    from api.models.settings import AppSetting
    await db.execute(delete(AppSetting).where(AppSetting.key == sync_pause.KEY))
    await db.commit()


@pytest.mark.asyncio
async def test_only_admins_pause_and_every_change_is_audited(db, client_admin, client_read_only, client_it_user):
    from api.models.settings import AuditLog
    await _clear(db)
    for c in (client_read_only, client_it_user):
        assert (await c.get("/api/v1/integrations/sync-pause")).status_code in (401, 403, 404)
        assert (await c.put("/api/v1/integrations/sync-pause", json={"paused": True})).status_code in (401, 403, 404)
    assert (await client_admin.get("/api/v1/integrations/sync-pause")).json()["paused"] is None
    assert (await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": True, "minutes": 7})).status_code == 400
    assert (await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": True, "minutes": 1e9})).status_code in (400, 422)
    assert (await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": True, "extra": 1})).status_code == 422
    r = (await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": True, "minutes": 30})).json()["paused"]
    assert r["by"] and r["until"]
    r = (await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": True, "minutes": None})).json()["paused"]
    assert r["until"] is None                     # until someone resumes it
    assert (await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": False})).json()["paused"] is None
    acts = [a for (a,) in (await db.execute(select(AuditLog.action).where(AuditLog.action.like("integrations.sync_%")))).all()]
    assert acts.count("integrations.sync_paused") >= 2 and "integrations.sync_resumed" in acts
    await _clear(db)


@pytest.mark.asyncio
async def test_while_paused_nothing_new_syncs_and_a_timed_pause_ends(db, client_admin, monkeypatch):
    from api.core import sync_pause
    from api.integrations import base
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AppSetting
    await _clear(db)
    cfg = IntegrationConfig(vendor=Vendor.zscaler, name=f"Pause {uuid.uuid4().hex[:6]}", is_enabled=True, config={},
                            sync_schedule="*/5 * * * *")
    db.add(cfg)
    await db.commit()
    started = []
    import api.core.tasks as tasks
    monkeypatch.setattr(tasks.sync_integration, "delay", lambda i: started.append(i) or type("T", (), {"id": "t"})())

    async def never(*a, **k):
        raise AssertionError("a paused install must not sync")
    monkeypatch.setattr(base, "_sync_by_id", never)
    await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": True, "minutes": 60})
    await base.run_due_syncs(db)
    assert str(cfg.id) not in started                                   # the schedule starts nothing
    assert await base.sync_by_id(db, str(cfg.id)) is False              # one already queued bows out
    r = await client_admin.post(f"/api/v1/integrations/{cfg.id}/sync")
    assert r.status_code == 409 and "paused" in r.json()["detail"]     # Sync Now says why
    # A timed pause that has run out is over, without anyone resuming it
    row = (await db.execute(select(AppSetting).where(AppSetting.key == sync_pause.KEY))).scalar_one()
    v = json.loads(row.value)
    v["until"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    row.value = json.dumps(v)
    await db.commit()
    assert not await sync_pause.paused(db)
    await base.run_due_syncs(db)
    assert str(cfg.id) in started
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cfg.id))
    await db.commit()
    await _clear(db)


@pytest.mark.asyncio
async def test_a_shipper_is_told_to_send_again_while_paused(client, client_admin, db):
    from tests.test_collector import _auth, _enroll
    await _clear(db)
    p, r, _ = await _enroll(client, client_admin)
    tok, iid = r.json()["token"], p["modules"]["ldap"]["integration_id"]
    body = {"kind": "ldap", "run_id": str(uuid.uuid4()), "users": [{"username": f"sp-{uuid.uuid4().hex[:6]}"}]}
    await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": True, "minutes": 30})
    r = await client.post(f"/api/v1/collector/ingest/{iid}", headers=_auth(tok), json=body)
    assert r.status_code == 409 and "send again" in r.json()["detail"]
    await client_admin.put("/api/v1/integrations/sync-pause", json={"paused": False})
    r = await client.post(f"/api/v1/collector/ingest/{iid}", headers=_auth(tok), json=body)
    assert r.status_code == 200 and r.json()["accepted"] == 1
    await _clear(db)


def test_a_damaged_setting_never_stops_syncing():
    from api.core.sync_pause import _parse
    assert _parse("not json") is None and _parse("[]") is None and _parse('{"by": "x"}') is None
