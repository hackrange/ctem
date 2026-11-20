"""GRC > control check page: the items to remediate, paged, searchable, linked to devices, audited."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select


async def _fleet(db, tag):
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    now = datetime.now(timezone.utc)
    cfg = IntegrationConfig(vendor=Vendor.crowdstrike, name=f"cs-{tag}", is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    db.add(SyncJob(integration_id=str(cfg.id), vendor="crowdstrike", status=SyncStatus.success, started_at=now, finished_at=now))
    devs = [Device(hostname=f"{tag}-{n}", device_type=DeviceType.workstation, edr_active=edr, os=os_, last_seen=now)
            for n, edr, os_ in (("b", False, "Windows 11"), ("a", False, "Ubuntu 24.04"), ("c", True, "Windows 11"))]
    db.add_all(devs)
    await db.commit()
    return devs


@pytest.mark.asyncio
async def test_items_list_the_devices_to_fix(db, client_admin):
    from api.models.settings import AuditLog
    tag = f"ck{uuid.uuid4().hex[:6]}"
    devs = await _fleet(db, tag)
    url = "/api/v1/grc/checks/ctem_edr_coverage/items"
    d = (await client_admin.get(url, params={"q": tag, "sort": "hostname", "order": "desc"})).json()
    assert d["check"]["check_type"] == "ctem_edr_coverage" and d["result"] in ("pass", "warning", "fail")
    assert [i["hostname"].lower() for i in d["items"]] == [f"{tag}-b", f"{tag}-a"]  # only the ones without EDR
    assert d["items"][0]["device_id"] == str(devs[0].id) and d["total"] == 2
    assert (await client_admin.get(url, params={"q": tag, "limit": 1, "offset": 1})).json()["items"][0]["hostname"].lower() == f"{tag}-b"  # default order is by hostname
    ubuntu = (await client_admin.get(url, params={"q": f"{tag}-a"})).json()
    assert ubuntu["total"] == 1
    # an unknown sort column is ignored, not passed anywhere
    assert (await client_admin.get(url, params={"q": tag, "sort": "password"})).status_code == 200
    acts = (await db.execute(select(AuditLog.action).where(AuditLog.resource_id == "ctem_edr_coverage"))).scalars().all()
    assert "grc_check_items" in acts


@pytest.mark.asyncio
async def test_items_need_grc_read_and_a_known_check(client_admin, client_it_user, client_no_auth):
    assert (await client_admin.get("/api/v1/grc/checks/ctem_nope/items")).status_code == 404
    assert (await client_it_user.get("/api/v1/grc/checks/ctem_edr_coverage/items")).status_code == 403
    assert (await client_no_auth.get("/api/v1/grc/checks/ctem_edr_coverage/items")).status_code in (401, 403)
    assert (await client_admin.get("/api/v1/grc/checks/ctem_edr_coverage/items", params={"limit": 500})).status_code == 422


@pytest.mark.asyncio
async def test_published_report_keeps_only_its_columns(db, client_admin):
    await _fleet(db, f"rp{uuid.uuid4().hex[:6]}")
    rep = (await client_admin.get("/api/v1/grc/checks/ctem_edr_coverage/report", params={"format": "json"})).json()
    assert rep["rows"] and all(set(r) == set(rep["columns"]) for r in rep["rows"])  # device_id stays inside CTEM
