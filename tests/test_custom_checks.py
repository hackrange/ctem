"""Custom control checks from a curated rule: validated, built from allow-listed filters, used like built-ins."""
from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.models.base import Base

NOW = datetime.now(timezone.utc)
AD_ONLY = {"schema": "open-ctem/custom-check@1", "name": "AD-only stale computers", "id": "ad_only_stale",
           "measure": "count", "population": {"ad_joined": True, "device_types": ["workstation", "server"]},
           "match": {"sources_only": ["LDAP"], "ad_stale_days": 90}, "thresholds": {"pass_max": 0, "warn_max": 5}}


@pytest_asyncio.fixture
async def gdb():
    path = tempfile.mktemp(prefix="ctem_custom_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(path)


async def _ad(db):
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    cfg = IntegrationConfig(vendor=Vendor.ldap, name="ad", is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    db.add(SyncJob(integration_id=str(cfg.id), vendor="ldap", status=SyncStatus.success, started_at=NOW, finished_at=NOW))
    old, recent = NOW - timedelta(days=200), NOW - timedelta(days=3)
    for h, t, src, logon in (("ws-gone", DeviceType.workstation, ",ldap,", old),       # the one to find
                             ("ws-never", DeviceType.workstation, ",ldap,", None),     # never logged on: stale too
                             ("ws-live", DeviceType.workstation, ",ldap,", recent),
                             ("srv-managed", DeviceType.server, ",crowdstrike,ldap,", old),  # another tool sees it
                             ("sw-old", DeviceType.network_device, ",ldap,", old)):    # outside the population
        db.add(Device(hostname=h, device_type=t, sources=src, ad_joined=True, ad_last_logon=logon, last_seen=NOW))
    await db.commit()


def _row(doc):
    from api.models.rules import CuratedRule
    from api.rules.custom import CheckDoc
    d = CheckDoc.model_validate(doc)
    return CuratedRule(id=str(uuid.uuid4()), name=d.name, check_type=d.check_type, document=d.dump(), version=1), d


@pytest.mark.parametrize("doc,msg", [
    ({**AD_ONLY, "match": {}}, "match needs at least one condition"),
    ({**AD_ONLY, "id": "Bad Id"}, "id"),
    ({**AD_ONLY, "thresholds": {"pass_at": 90}}, "takes thresholds"),
    ({**AD_ONLY, "thresholds": {"pass_max": 9, "warn_max": 2}}, "warn_max must be at least pass_max"),
    ({**AD_ONLY, "match": {"sources_only": ["nope"]}}, "unknown source"),
    ({**AD_ONLY, "match": {"ad_stale_days": 0}}, "ad_stale_days"),
    ({**AD_ONLY, "run": "rm -rf"}, "Extra inputs"),
])
def test_definition_validation(doc, msg):
    from pydantic import ValidationError

    from api.rules.custom import CheckDoc
    with pytest.raises(ValidationError) as exc:
        CheckDoc.model_validate(doc)
    assert msg in str(exc.value)


@pytest.mark.asyncio
async def test_count_check_finds_stale_ad_only_computers(gdb):
    from api.grc.checks import evaluate
    from api.rules.custom import build
    await _ad(gdb)
    row, doc = _row(AD_ONLY)
    check = build(row, doc)
    assert check.check_type == "ctem_custom_ad_only_stale" and check.sources == ("ldap",)
    body, out = await evaluate(gdb, check, {}, detail=True, rules=[])
    assert body["details"] == {"population": 4, "matching": 2, "matching_pct": 50.0}
    assert body["result"] == "warning"   # 2 is within warn_max 5
    assert sorted(r["hostname"].lower() for r in out.rows) == ["ws-gone", "ws-never"]
    assert out.rows[0]["ad_last_logon"] and "ad_last_logon" in out.columns


@pytest.mark.asyncio
async def test_percent_check_lists_the_devices_that_miss(gdb):
    from api.grc.checks import evaluate
    from api.rules.custom import build
    await _ad(gdb)
    doc = {**AD_ONLY, "id": "managed_ad", "measure": "percent", "match": {"sources": ["crowdstrike"]}, "thresholds": {}}
    row, d = _row(doc)
    body, out = await evaluate(gdb, build(row, d), {}, detail=True, rules=[])
    assert body["details"]["meeting"] == 1 and body["result"] == "fail"
    assert "srv-managed" not in {r["hostname"].lower() for r in out.rows} and len(out.rows) == 3


@pytest.mark.asyncio
async def test_api_create_use_like_a_builtin_then_disable(client_admin, client_cyber):
    ident = f"t{uuid.uuid4().hex[:8]}"
    doc = {**AD_ONLY, "id": ident, "name": f"Custom {ident}"}
    ct = f"ctem_custom_{ident}"
    assert (await client_cyber.post("/api/v1/rules", json={"document": doc})).status_code == 403
    pv = (await client_admin.post("/api/v1/rules/preview", json={"document": doc})).json()
    assert pv["kind"] == "check" and pv["check_type"] == ct and "result" in pv["after"]
    r = await client_admin.post("/api/v1/rules", json={"document": doc})
    assert r.status_code == 201 and r.json()["check"] == ct
    rid = r.json()["id"]
    assert (await client_admin.post("/api/v1/rules", json={"document": {**doc, "name": "dupe"}})).status_code == 409
    assert ct in {c["check_type"] for c in (await client_admin.get("/api/v1/grc/checks")).json()["checks"]}
    assert (await client_admin.get(f"/api/v1/grc/checks/{ct}")).json()["name"] == doc["name"]
    assert (await client_admin.get(f"/api/v1/grc/checks/{ct}/items")).status_code == 200
    overview = {c["check_type"]: c for c in (await client_admin.get("/api/v1/grc/overview")).json()["checks"]}
    assert overview[ct]["custom"] is True
    # A scoping rule can't target a custom check; the check has its own population
    scope = {"schema": "open-ctem/curated-rule@1", "name": "x", "check": ct, "scope": {"include": {"device_types": ["server"]}}}
    assert (await client_admin.post("/api/v1/rules/validate", json={"document": scope})).json()["valid"] is False
    await client_admin.put(f"/api/v1/rules/{rid}/enabled", json={"enabled": False})
    assert (await client_admin.get(f"/api/v1/grc/checks/{ct}")).status_code == 404
    assert (await client_admin.delete(f"/api/v1/rules/{rid}")).status_code == 204


def test_sources_only_needs_nothing_else(tmp_path):
    from api.rules.doc import Filters
    f = Filters.model_validate({"sources_only": ["ldap", "Rapid7 InsightVM"]})
    assert f.sources_only == ["ldap", "rapid7_insightvm"]


@pytest.mark.asyncio
async def test_flagged_inventory_but_online_is_miscategorized(gdb):
    from api.grc.checks import evaluate
    from api.models.device import Device, DeviceAssignment, DeviceType
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    cfg = IntegrationConfig(vendor=Vendor.crowdstrike, name="cs", is_enabled=True, config={})
    gdb.add(cfg)
    await gdb.flush()
    gdb.add(SyncJob(integration_id=str(cfg.id), vendor="crowdstrike", status=SyncStatus.success, started_at=NOW, finished_at=NOW))
    week = NOW - timedelta(days=7)
    devs = {}
    for h, status, seen, edr in (("stolen-online", "stolen", week, NOW - timedelta(hours=2)),  # EDR checked in today
                                 ("lost-quiet", "lost", week, None),
                                 ("inuse-online", None, NOW, NOW)):
        devs[h] = Device(hostname=h, device_type=DeviceType.workstation, last_seen=seen, edr_last_seen=edr)
        gdb.add(devs[h])
        await gdb.flush()
        if status:
            gdb.add(DeviceAssignment(device_id=devs[h].id, status=status))
    await gdb.commit()
    doc = {"schema": "open-ctem/custom-check@1", "name": "Flagged but online", "id": "flagged_online", "measure": "count",
           "population": {"inventory_status": ["shipped", "lost", "stolen", "returned"]}, "match": {"seen_within_days": 1}}
    row, d = _row(doc)
    body, out = await evaluate(gdb, build_check(row, d), {}, detail=True, rules=[])
    assert body["details"] == {"population": 2, "matching": 1, "matching_pct": 50.0} and body["result"] == "warning"
    assert [r["hostname"].lower() for r in out.rows] == ["stolen-online"]
    in_use = _row({**doc, "id": "in_use_only", "population": {"inventory_status": ["in_use"]}})
    body, _ = await evaluate(gdb, build_check(*in_use), {}, rules=[])
    assert body["details"]["population"] == 1


def build_check(row, doc):
    from api.rules.custom import build
    return build(row, doc)


@pytest.mark.asyncio
async def test_empty_population_passes_a_count_but_not_a_percent(gdb):
    from api.grc.checks import evaluate
    await _ad(gdb)
    doc = {"schema": "open-ctem/custom-check@1", "name": "Flagged but online", "id": "flagged_online", "measure": "count",
           "population": {"inventory_status": ["stolen"]}, "match": {"seen_within_days": 1}}
    body, _ = await evaluate(gdb, build_check(*_row(doc)), {}, rules=[])
    assert body["result"] == "pass" and body["details"]["population"] == 0
    body, _ = await evaluate(gdb, build_check(*_row({**doc, "measure": "percent"})), {}, rules=[])
    assert body["result"] == "error"
