"""CrowdStrike Spotlight on or off with one switch: the shipper's own Spotlight setting, also on the integration's card
(admins, audited). The box gets it on its next config; while it's off CTEM drops any Spotlight data that still arrives
and a full pass closes nothing."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from tests.test_cs_alert_actions import _shipper
from tests.test_cs_spotlight import VULN, cse


@pytest.mark.asyncio
async def test_the_card_switch_is_the_shippers_spotlight_setting(db, client, client_admin, client_cyber):
    from api.models.settings import AuditLog
    iid, tok = await _shipper(client, client_admin)
    card = next(i for i in (await client_admin.get("/api/v1/integrations")).json()["integrations"] if i["id"] == iid)
    assert card["spotlight"] is True                                   # on unless switched off
    async def box_config():   # what the box gets at its next check-in
        return (await client.post("/api/v1/collector/checkin", headers={"Authorization": f"Bearer {tok}"},
                                  json={"hostname": "server001", "agent_version": "1.8.0"})).json()
    before = (await box_config())["config_version"]
    for c in (client_cyber,):
        assert (await c.put(f"/api/v1/integrations/{iid}/spotlight", json={"enabled": False})).status_code in (401, 403, 404)
    assert (await client_admin.put(f"/api/v1/integrations/{iid}/spotlight", json={"enabled": "no"})).status_code == 422
    assert (await client_admin.put(f"/api/v1/integrations/{uuid.uuid4()}/spotlight", json={"enabled": False})).status_code == 404
    r = await client_admin.put(f"/api/v1/integrations/{iid}/spotlight", json={"enabled": False})
    assert r.status_code == 200 and r.json() == {"spotlight": False}
    cfg = await box_config()
    cs = next(m for m in cfg["modules"] if m["kind"] == "crowdstrike")
    assert cs["settings"]["spotlight"] == "off" and cfg["config_version"] > before   # the box picks it up
    assert cs["settings"]["alert_updates"] == "on"                                     # nothing else changed
    card = next(i for i in (await client_admin.get("/api/v1/integrations")).json()["integrations"] if i["id"] == iid)
    assert card["spotlight"] is False
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "integration.spotlight",
                                                    AuditLog.resource_id == iid))).scalars().first()
    await client_admin.put(f"/api/v1/integrations/{iid}/spotlight", json={"enabled": True})
    assert next(i for i in (await client_admin.get("/api/v1/integrations")).json()["integrations"] if i["id"] == iid)["spotlight"]


@pytest.mark.asyncio
async def test_while_off_spotlight_data_is_dropped_and_nothing_is_closed(db, client, client_admin):
    from api.collector.ingest import apply_batch
    from api.collector.schemas import CrowdStrikeBatch
    from api.integrations.crowdstrike_spotlight import SOURCE
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding
    iid, _tok = await _shipper(client, client_admin)
    aid = uuid.uuid4().hex
    db.add(Device(hostname=f"ws-sw-{aid[:6]}", device_type=DeviceType.workstation, edr_device_id=aid, edr_vendor="crowdstrike"))
    await db.commit()
    batch = CrowdStrikeBatch.model_validate({"kind": "crowdstrike", "run_id": str(uuid.uuid4()), "spotlight_mode": "full",
                                             "spotlight_cves": [cse._cve(VULN["cve"])], "spotlight": [cse._vuln(dict(VULN, aid=aid))]})
    await client_admin.put(f"/api/v1/integrations/{iid}/spotlight", json={"enabled": False})
    await apply_batch(db, batch, iid)
    await db.commit()
    assert not (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.source_id == f"{aid}:CVE-2026-1111"))).scalars().first()
    await client_admin.put(f"/api/v1/integrations/{iid}/spotlight", json={"enabled": True})
    await apply_batch(db, batch, iid)
    await db.commit()
    assert (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.source_id == f"{aid}:CVE-2026-1111"))).scalar_one()
