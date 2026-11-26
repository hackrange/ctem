"""Abandoned sync runs: closed when another worker start left them, or after 6 hours; collector runs left alone."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

NOW = datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_reap_closes_only_abandoned_runs(db):
    from api.core.tasks_reap import INTERRUPTED, TOO_LONG, reap
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    pulled = IntegrationConfig(vendor=Vendor.rapid7_insightvm, name=f"R7 {uuid.uuid4().hex[:6]}", config={})
    pushed = IntegrationConfig(vendor=Vendor.ldap, name=f"LDAP {uuid.uuid4().hex[:6]}", config={"mode": "collector"})
    db.add_all([pulled, pushed])
    await db.commit()
    me, earlier, dead = "worker:hosta:aaaaaaaaaaaa", "worker:hosta:bbbbbbbbbbbb", "worker:hostc:dddddddddddd"
    other_live = "worker:hostb:cccccccccccc"

    def job(cfg, runner, hours_ago, status=SyncStatus.running):
        return SyncJob(integration_id=str(cfg.id), vendor=cfg.vendor.value, status=status, runner=runner,
                       started_at=NOW - timedelta(hours=hours_ago))
    jobs = {
        "earlier_start": job(pulled, earlier, 0.2),      # this host's earlier worker start: closed at once
        "dead_host": job(pulled, dead, 0.2),             # a host no worker answers from: closed at once
        "other_live": job(pulled, other_live, 0.2),      # a second worker that is up: left alone
        "mine": job(pulled, me, 0.2),                     # this worker's own: left alone
        "mine_hung": job(pulled, me, 7),                  # this worker's, but 7 hours: closed by the backstop
        "app_recent": job(pulled, "app", 1),              # the app's: left alone
        "legacy_old": job(pulled, None, 19),              # from before runner ids: closed after 6 hours
        "collector_old": job(pushed, None, 9),            # a collector closes its own: left alone
        "done": job(pulled, earlier, 3, SyncStatus.success),  # finished: untouched
    }
    db.add_all(jobs.values())
    await db.commit()
    ids = {k: j.id for k, j in jobs.items()}
    assert await reap(db, None, me, NOW) == 2   # no ping answer: only the 6-hour backstop
    assert await reap(db, {"hosta", "hostb"}, me, NOW) == 2
    got = {j.id: j for j in (await db.execute(select(SyncJob).where(SyncJob.id.in_(ids.values()))
                                              .execution_options(populate_existing=True))).scalars()}
    st = {k: (got[i].status, got[i].error_message) for k, i in ids.items()}
    assert st["earlier_start"] == st["dead_host"] == (SyncStatus.failed, INTERRUPTED)
    assert st["mine_hung"] == (SyncStatus.failed, TOO_LONG) and st["legacy_old"] == (SyncStatus.failed, TOO_LONG)
    for k in ("mine", "other_live", "app_recent", "collector_old"):
        assert st[k][0] == SyncStatus.running, k
    assert st["done"] == (SyncStatus.success, None)
    assert got[ids["dead_host"]].finished_at is not None
    assert await reap(db, {"hosta", "hostb"}, me, NOW) == 0   # nothing left to close
    await db.execute(delete(SyncJob).where(SyncJob.id.in_(ids.values())))
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id.in_([pulled.id, pushed.id])))
    await db.commit()


def test_which_locks_and_runs_are_abandoned():
    from api.core.tasks_reap import abandoned
    me, live = "worker:hosta:aaaaaaaaaaaa", {"hosta", "hostb"}
    assert abandoned("worker:hosta:bbbbbbbbbbbb|0123456789abcdef", live, me)       # an earlier start here
    assert abandoned("worker:hostc:dddddddddddd|0123456789abcdef", live, me)       # nobody answers from hostc
    assert not abandoned("worker:hostb:cccccccccccc|0123456789abcdef", live, me)   # hostb is up
    assert not abandoned("worker:hosta:aaaaaaaaaaaa|0123456789abcdef", live, me)   # this worker's
    assert not abandoned("app|0123456789abcdef", live, me) and not abandoned("0123456789abcdef", live, me)
    assert not abandoned(None, live, me) and not abandoned("", live, me) and not abandoned("worker::x", live, me)


@pytest.mark.asyncio
async def test_sync_job_and_lock_carry_the_runner(db, monkeypatch):
    from api.integrations import base
    from api.models.integration import IntegrationConfig, SyncJob, Vendor
    cfg = IntegrationConfig(vendor=Vendor.zscaler, name=f"Z {uuid.uuid4().hex[:6]}", config={})
    db.add(cfg)
    await db.commit()
    seen = {}

    async def lock(integration_id, runner="app"):
        seen["lock"] = runner
        return None

    class Fake:
        integration_id = None

        async def sync(self, db):
            return 3
    monkeypatch.setattr(base, "_sync_lock", lock)
    monkeypatch.setattr(base, "get_connector", lambda vendor, config: Fake())
    assert await base.sync_by_id(db, str(cfg.id), "worker:hostz:cccccccccccc")
    row = (await db.execute(select(SyncJob).where(SyncJob.integration_id == str(cfg.id)))).scalar_one()
    assert row.runner == "worker:hostz:cccccccccccc" and seen["lock"] == "worker:hostz:cccccccccccc"
    await db.execute(delete(SyncJob).where(SyncJob.integration_id == str(cfg.id)))
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cfg.id))
    await db.commit()
