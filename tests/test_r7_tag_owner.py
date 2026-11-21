"""Rapid7 tags: the Cloud feed owns them when it's on, the tag list filters by prefix, and
a sync that expunges its session still records how it ended."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select


def _n() -> str:
    return f"r7own-{uuid.uuid4().hex[:8]}"


async def _tags_of(db, host_key):
    from api.models.device import Device, DeviceTag
    from api.models.tag import Tag
    dev = (await db.execute(select(Device).where(Device.host_key == host_key))).scalar_one()
    names = (await db.execute(select(Tag.name).join(DeviceTag, DeviceTag.tag_id == Tag.id)
                              .where(DeviceTag.device_id == dev.id))).scalars().all()
    return dev, set(names)


@pytest.mark.asyncio
async def test_console_leaves_tags_to_an_enabled_cloud_feed(db):
    from api.integrations.rapid7_insightvm import InsightVMConnector
    from api.models.integration import IntegrationConfig, Vendor

    n, conn = _n(), InsightVMConnector({})
    owners = [{"type": "owner", "name": "E-O: Pat Example"}, {"type": "criticality", "name": "High"}]
    await conn._console_upsert_assets([{"hostName": f"{n}.ad.acme.example", "tags": owners}], db)
    dev, names = await _tags_of(db, n)
    assert "owner:E-O: Pat Example" in names and dev.criticality == "High"

    cloud = IntegrationConfig(vendor=Vendor.rapid7_insightvm, name=f"cloud-{n}", is_enabled=True,
                              config={"mode": "cloud", "api_key": "k", "region": "us"})
    db.add(cloud)
    await db.commit()
    try:
        # The console now reports no tags (its tag API missed them); the Cloud feed's stay
        await conn._console_upsert_assets([{"hostName": f"{n}.ad.acme.example", "tags": []}], db)
        dev, names = await _tags_of(db, n)
        assert "owner:E-O: Pat Example" in names and dev.criticality == "High"
    finally:
        await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cloud.id))
        await db.commit()

    # Cloud off again: the console owns tags and its view applies
    await conn._console_upsert_assets([{"hostName": f"{n}.ad.acme.example", "tags": []}], db)
    dev, names = await _tags_of(db, n)
    assert not any(x.startswith("owner:") for x in names) and dev.criticality is None


def test_cloud_config_detection():
    from api.integrations.rapid7_insightvm_console import is_cloud_config
    assert is_cloud_config({"mode": "cloud"})
    assert is_cloud_config({"api_key": "k"})
    assert not is_cloud_config({"mode": "collector", "api_key": "k"})
    assert not is_cloud_config({"mode": "console", "api_key": "k"})
    assert not is_cloud_config({"username": "u", "password": "p"})


@pytest.mark.asyncio
async def test_tag_list_by_prefix_and_in_use(db, client_read_only):
    from api.core.device_tags import sync_tags
    from api.models.device import Device
    from api.models.tag import Tag

    n = _n()
    dev = Device(hostname=f"{n}.acme.example")
    db.add(dev)
    await db.flush()
    await sync_tags(db, dev.id, {f"owner:T-O: {n}", f"r7:app: {n}"}, ("owner:", "r7:"), "rapid7_insightvm", {})
    db.add(Tag(name=f"owner:T-O: unused {n}", source="rapid7_insightvm"))
    db.add(Tag(name=f"owner:T_O: {n}", source="rapid7_insightvm"))  # "_" must not act as a wildcard
    await db.commit()

    r = await client_read_only.get("/api/v1/tags", params={"prefix": "owner:T-O:", "in_use": "true", "limit": 2000})
    names = {t["name"] for t in r.json()["tags"]}
    assert f"owner:T-O: {n}" in names
    assert f"owner:T-O: unused {n}" not in names and f"owner:T_O: {n}" not in names
    assert not any(x.startswith("r7:") for x in names)

    r = await client_read_only.get("/api/v1/tags", params=[("prefix", "owner:T-O:"), ("prefix", "r7:app:"),
                                                           ("limit", "2000")])
    names = {t["name"] for t in r.json()["tags"]}
    assert {f"owner:T-O: {n}", f"r7:app: {n}", f"owner:T-O: unused {n}"} <= names

    assert (await client_read_only.get("/api/v1/tags", params={"limit": 999999})).status_code == 422


@pytest.mark.asyncio
async def test_sync_outcome_is_saved_even_after_expunge(db, monkeypatch):
    from api.integrations import base
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor

    class Expunger(base.BaseConnector):
        async def test_connection(self):
            return True

        async def sync(self, s):
            s.expunge_all()
            return 7

    cfg = IntegrationConfig(vendor=Vendor.crowdstrike, name=f"x-{_n()}", is_enabled=True, config={})
    db.add(cfg)
    await db.commit()
    monkeypatch.setattr(base, "get_connector", lambda vendor, config: Expunger(config))
    try:
        assert await base._sync_by_id(db, str(cfg.id)) is True
        job = (await db.execute(select(SyncJob).where(SyncJob.integration_id == str(cfg.id))
                                .execution_options(populate_existing=True))).scalar_one()
        assert job.status == SyncStatus.success and job.records_imported == 7 and job.finished_at
        got = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == cfg.id)
                                .execution_options(populate_existing=True))).scalar_one()
        assert got.last_sync_status == SyncStatus.success and got.last_sync_at
    finally:
        await db.execute(delete(SyncJob).where(SyncJob.integration_id == str(cfg.id)))
        await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cfg.id))
        await db.commit()
