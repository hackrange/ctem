"""Truncating an integration: its source's data goes, shared assets stay, decisions stay, admins only, name to confirm."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select


async def _seed(db):
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AppSetting
    from api.models.vuln import ExceptionScope, ExceptionStatus, Finding, Vulnerability, VulnException
    n = uuid.uuid4().hex[:6]
    cfg = IntegrationConfig(vendor=Vendor.zscaler, name=f"ACME Zscaler {n}", is_enabled=True, config={})
    twin = IntegrationConfig(vendor=Vendor.zscaler, name=f"ACME Zscaler lab {n}", is_enabled=True, config={})
    only = Device(hostname=f"zs-only-{n}", device_type=DeviceType.workstation, source="zscaler", sources=",zscaler,")
    both = Device(hostname=f"zs-both-{n}", device_type=DeviceType.workstation, source="ldap", sources=",ldap,zscaler,",
                  edr_vendor="zscaler", edr_active=True)
    v1 = Vulnerability(source="zscaler", source_vuln_id=f"a-{n}", title=f"a {n}", cvss_base=9.8)
    v2 = Vulnerability(source="zscaler", source_vuln_id=f"b-{n}", title=f"b {n}", cvss_base=9.8)
    v3 = Vulnerability(source="ldap_test", source_vuln_id=f"c-{n}", title=f"c {n}", cvss_base=5.0)
    db.add_all([cfg, twin, only, both, v1, v2, v3])
    await db.flush()
    db.add_all([Finding(device_id=only.id, vuln_id=v1.id, source="zscaler"), Finding(device_id=both.id, vuln_id=v2.id, source="zscaler"),
                Finding(device_id=both.id, vuln_id=v3.id, source="ldap_test"),
                VulnException(vuln_id=v2.id, scope=ExceptionScope.all, reason="accepted for the test", status=ExceptionStatus.approved, requested_by="tester", requested_at=datetime.now(timezone.utc),
                              expires_at=datetime.now(timezone.utc) + timedelta(days=30)),
                AppSetting(key=f"threat_alert_{n}", value=json.dumps({"source": "zscaler", "id": n})),
                AppSetting(key=f"sync_state.{cfg.id}", value="{}")])
    await db.commit()
    return cfg, twin, only, both, v1, v2


@pytest.mark.asyncio
async def test_truncate_removes_the_source_and_keeps_the_rest(db):
    from api.core import integration_truncate as tr
    from api.models.device import Device
    from api.models.integration import IntegrationConfig
    from api.models.settings import AppSetting
    from api.models.vuln import Finding, Vulnerability
    cfg, twin, only, both, v1, v2 = await _seed(db)
    ids = {k: str(o.id) for k, o in (("cfg", cfg), ("twin", twin), ("only", only), ("both", both), ("v1", v1), ("v2", v2))}
    p = await tr.preview(db, cfg)
    assert p["findings"] >= 2 and p["assets_deleted"] >= 1 and p["assets_kept"] >= 1 and twin.name in p["shared_with"]
    out = await tr.run(db, cfg, "admin-test")
    assert out["findings"] >= 2 and out["assets_deleted"] >= 1
    db.expire_all()
    assert await db.get(Device, ids['only']) is None
    kept = await db.get(Device, ids['both'])
    assert kept.sources == ",ldap," and kept.edr_vendor is None and kept.edr_active is False
    left = (await db.execute(select(Finding.source).where(Finding.device_id == ids['both']))).scalars().all()
    assert left == ["ldap_test"]                                             # other sources' findings stay
    assert await db.get(Vulnerability, ids['v1']) is None                        # no finding left: gone
    assert await db.get(Vulnerability, ids['v2']) is not None                    # carries an exception: kept
    keys = {k for (k,) in (await db.execute(select(AppSetting.key))).all()}
    assert f"sync_state.{ids['cfg']}" not in keys and out["alerts"] >= 1
    for c in (ids["cfg"], ids["twin"]):
        c2 = await db.get(IntegrationConfig, c)
        assert c2.last_sync_at is None and "truncated by admin-test" in c2.last_sync_error


@pytest.mark.asyncio
async def test_truncate_api_is_admin_only_and_needs_the_name(db, client_admin, client_cyber, monkeypatch):
    from api.core import integration_truncate as tr
    from api.core import tasks
    from api.models.integration import IntegrationConfig, Vendor
    cfg = IntegrationConfig(vendor=Vendor.zscaler, name=f"ACME Zscaler api {uuid.uuid4().hex[:6]}", is_enabled=True, config={})
    ai = IntegrationConfig(vendor=Vendor.anthropic, name="ACME AI", is_enabled=True, config={})
    db.add_all([cfg, ai])
    await db.commit()

    async def idle(_):
        return False
    monkeypatch.setattr(tr, "running", idle)
    queued = []
    monkeypatch.setattr(tasks.truncate_integration, "delay", lambda *a: queued.append(a))
    url = f"/api/v1/integrations/{cfg.id}/truncate"
    assert (await client_cyber.get(url)).status_code == 403
    assert (await client_cyber.post(url, json={"confirm": cfg.name})).status_code == 403
    p = (await client_admin.get(url)).json()
    assert p["truncatable"] and p["name"] == cfg.name and p["running"] is False
    assert (await client_admin.post(url, json={"confirm": "wrong"})).status_code == 400
    assert (await client_admin.post(f"/api/v1/integrations/{ai.id}/truncate", json={"confirm": "ACME AI"})).status_code == 400
    assert (await client_admin.get(f"/api/v1/integrations/{uuid.uuid4()}/truncate")).status_code == 404
    r = await client_admin.post(url, json={"confirm": cfg.name})
    assert r.status_code == 202 and queued and queued[0][0] == str(cfg.id)
    assert (await client_admin.get("/api/v1/integrations")).json()["can_truncate"] is True
