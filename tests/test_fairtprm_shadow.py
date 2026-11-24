"""Shadow SaaS / AI checks accept Grip or FairTPRM, never pass on missing data, and don't double count."""
from __future__ import annotations

import contextlib
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.models.base import Base

APPS = [
    {"id": 1, "name": "ChatThing", "domain": "chatthing.example", "users": 40, "risk_score": 85, "status": "pending",
     "sanction_tag": "unsanctioned", "ai_depth_level": "AI-Native App", "last_seen": "2026-11-19 10:00:00"},
    {"id": 2, "name": "FileShare", "domain": "fileshare.example", "users": 12, "risk_score": 30, "status": "pending",
     "sanction_tag": "untagged", "ai_depth_level": "No AI"},
    {"id": 3, "name": "Slacky", "domain": "slacky.example", "users": 300, "status": "onboarded", "sanction_tag": None},
    {"id": 4, "name": "Ruled out", "domain": "x.example", "users": 5, "status": "dismissed"},
    {"id": 5, "name": "Approved AI", "domain": "ok.example", "users": 9, "status": "pending", "sanction_tag": "Sanctioned",
     "ai_depth_level": "AI-Powered"},
]


@pytest_asyncio.fixture
async def gdb():
    path = tempfile.mktemp(prefix="ctem_shadow_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(path)


class _Conn:
    def __init__(self, status=200, apps=APPS):
        self.status, self.apps, self.integration_id, self.calls = status, apps, None, []

    async def _get(self, client, path, params=None):
        from api.integrations.fairtprm import FairTPRMError
        self.calls.append((path, params))
        if self.status != 200:
            raise FairTPRMError("nope", self.status)
        off, lim = params["offset"], params["limit"]
        return {"data": self.apps[off:off + lim], "total": len(self.apps)}


async def _fairtprm_config(db):
    from api.models.integration import IntegrationConfig, Vendor
    cfg = IntegrationConfig(vendor=Vendor.fairtprm, name="FairTPRM", is_enabled=True, config={})
    db.add(cfg)
    await db.commit()
    return cfg


@pytest.mark.asyncio
async def test_fairtprm_inventory_feeds_both_checks(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.integrations.fairtprm_shadow import sync_shadow
    from api.models.identity import SaasAppRecord

    await _fairtprm_config(gdb)
    n, outcome = await sync_shadow(_Conn(), None, gdb)
    await gdb.commit()
    assert (n, outcome) == (4, "ok")  # the dismissed one is skipped
    recs = {r.external_id: r for r in (await gdb.execute(select(SaasAppRecord))).scalars()}
    assert recs["1"].is_shadow_ai and not recs["1"].is_sanctioned and recs["1"].risk_level == "critical"
    assert not recs["2"].is_shadow_ai and recs["3"].is_sanctioned and recs["5"].is_sanctioned

    ai, _ = await evaluate(gdb, REGISTRY["ctem_shadow_ai"], {})
    saas, _ = await evaluate(gdb, REGISTRY["ctem_shadow_saas"], {})
    assert ai["result"] == "warning" and ai["details"] == {"unsanctioned_apps": 1, "user_accounts": 40}  # 1 is within warn_max 3
    assert saas["result"] == "warning" and saas["details"]["unsanctioned_apps"] == 1
    assert ai["check_version"] == 2 and "fairtprm:shadow_saas" in ai["data_freshness"]

    # Grip's copy of the same app (named, not by domain) and a Grip-only app: FairTPRM is the only source while it reports
    gdb.add_all([SaasAppRecord(source="grip", external_id="g1", app_name="Same app", vendor="Same app", is_shadow_ai=True,
                               is_sanctioned=False, risk_level="high", user_count=40),
                 SaasAppRecord(source="grip", external_id="g2", app_name="Grip only", is_shadow_ai=True, is_sanctioned=False,
                               risk_level="high", user_count=3)])
    await gdb.commit()
    ai, _ = await evaluate(gdb, REGISTRY["ctem_shadow_ai"], {})
    assert ai["details"] == {"unsanctioned_apps": 1, "user_accounts": 40} and "FairTPRM" in ai["summary"]
    for r in (await gdb.execute(select(SaasAppRecord).where(SaasAppRecord.source == "grip"))).scalars():
        await gdb.delete(r)
    await gdb.commit()

    # Gone from FairTPRM -> gone here
    await sync_shadow(_Conn(apps=APPS[:1]), None, gdb)
    await gdb.commit()
    assert {r.external_id for r in (await gdb.execute(select(SaasAppRecord))).scalars()} == {"1"}


@pytest.mark.asyncio
@pytest.mark.parametrize("status,outcome", [(404, "unavailable"), (403, "denied")])
async def test_no_endpoint_or_no_access_is_no_data_not_a_pass(gdb, status, outcome):
    from api.grc.checks import REGISTRY, evaluate
    from api.integrations.fairtprm_shadow import sync_shadow

    await _fairtprm_config(gdb)
    assert await sync_shadow(_Conn(status=status), None, gdb) == (0, outcome)
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_shadow_ai"], {})
    assert body["result"] == "error" and "no successful sync yet" in body["summary"]


@pytest.mark.asyncio
async def test_with_fairtprm_reporting_grip_apps_and_agents_are_left_out(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.integrations.fairtprm_shadow import sync_shadow
    from api.models.identity import SaasAppRecord
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor

    await _fairtprm_config(gdb)
    await sync_shadow(_Conn(apps=APPS[:1]), None, gdb)
    grip = IntegrationConfig(vendor=Vendor.grip, name="Grip", is_enabled=True, config={})
    gdb.add(grip)
    await gdb.flush()
    at = datetime.now(timezone.utc) - timedelta(hours=1)
    gdb.add(SyncJob(integration_id=str(grip.id), vendor="grip", status=SyncStatus.success, started_at=at, finished_at=at))
    gdb.add(SaasAppRecord(source="grip", external_id="g1", app_name="ChatThing", vendor="ChatThing.example ",
                          is_shadow_ai=True, is_sanctioned=False, risk_level="high", user_count=55))
    gdb.add(SaasAppRecord(source="grip_ai_agent", external_id="a1", app_name="ChatThing", is_shadow_ai=True,
                          is_sanctioned=False, risk_level="medium", user_count=2))
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_shadow_ai"], {})
    # FairTPRM decides (exceptions are granted there): Grip's copy of the app and its agent are not counted again
    assert body["details"] == {"unsanctioned_apps": 1, "user_accounts": 40}
