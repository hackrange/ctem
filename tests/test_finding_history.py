"""Remediated findings past the retention window are rolled up, then removed, and nothing that reads history
changes: the device trend line, the org-wide trend, fix counts and mean time to remediate read the same before and
after. Device counts are written only when they change; old score history is thinned to one entry a week."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, func, select

NOW = datetime.now(timezone.utc)
KEEP = 300   # nothing else in the suite is remediated this long ago


async def _seed(db, tag):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    d = Device(hostname=f"hist-{tag}", device_type=DeviceType.server)
    crit = Vulnerability(source="test", source_vuln_id=f"c-{tag}", title="c", cvss_base=9.8, is_kev=True)
    low = Vulnerability(source="test", source_vuln_id=f"l-{tag}", title="l", cvss_base=3.0)
    db.add_all([d, crit, low])
    await db.flush()
    src = f"hist{tag}"
    old = Finding(device_id=d.id, vuln_id=crit.id, source=src, status=FindingStatus.remediated,
                  first_detected=NOW - timedelta(days=360), last_seen=NOW - timedelta(days=330))
    recent = Finding(device_id=d.id, vuln_id=low.id, source=src, status=FindingStatus.remediated,
                     first_detected=NOW - timedelta(days=40), last_seen=NOW - timedelta(days=10))
    still = Finding(device_id=d.id, vuln_id=low.id, source=src, status=FindingStatus.open, first_detected=NOW - timedelta(days=5))
    db.add_all([old, recent, still])
    await db.commit()
    return d, src, old.id


@pytest.mark.asyncio
async def test_removing_old_fixes_keeps_every_history_the_same(db, client_admin):
    from api.core import finding_history as fh
    from api.core.vuln_dashboard import _mttr, _trend
    from api.dashboards.m_risk import _mttr_between
    from api.models.finding_history import DeviceDailyCount, FindingRollup
    from api.models.settings import AppSetting
    from api.models.vuln import Finding, FindingStatus
    tag = uuid.uuid4().hex[:6]
    d, src, old_id = await _seed(db, tag)
    roll = fh.Roll(sources=(src,))
    w = [Finding.source == src]

    class Ctx:
        pass
    ctx = Ctx()
    ctx.db, ctx.scope = db, None
    fixed_w = w + [Finding.status == FindingStatus.remediated, Finding.first_detected.is_not(None)]
    year = (NOW - timedelta(days=365), NOW)

    pg = db.bind.dialect.name == "postgresql"   # the dashboard SQL is Postgres's; elsewhere only the device line is checked

    async def views():
        dev = (await client_admin.get(f"/api/v1/devices/{d.id}/trend", params={"days": 365})).json()
        line = {k: dev[k] for k in ("days", "open", "critical", "high")}
        if not pg:
            return (line,)
        return line, await _trend(db, w, 365, roll), await _mttr(db, w, roll), await _mttr_between(ctx, fixed_w, *year, roll)
    before = await views()
    assert max(before[0]["critical"]) == 1                            # the old critical shows a year back
    if pg:
        assert before[3] == (30.0, 2) and sum(before[1]["fixed"]) == 2   # 2 fixes, 30 days each
    try:
        assert await fh.purge_remediated(db, KEEP) >= 1
        assert await db.get(Finding, old_id) is None
        left = (await db.execute(select(func.count()).select_from(Finding).where(Finding.source == src))).scalar_one()
        assert left == 2                                                  # the recent fix and the open one stay
        rows = (await db.execute(select(FindingRollup).where(FindingRollup.source == src))).scalars().all()
        assert {(r.kind, r.severity, r.kev, r.n, r.timed) for r in rows} == {("new", "critical", True, 1, 0), ("fixed", "critical", True, 1, 1)}
        assert round(next(r.fix_days for r in rows if r.kind == "fixed")) == 30
        assert await views() == before                                    # trend, MTTR and the device line unchanged
        assert await fh.purge_remediated(db, KEEP) == 0                   # nothing twice
    finally:
        await db.execute(delete(FindingRollup).where(FindingRollup.source == src))
        await db.execute(delete(DeviceDailyCount))
        await db.execute(delete(AppSetting).where(AppSetting.key == fh.STATE_KEY))
        await db.commit()


@pytest.mark.asyncio
async def test_device_counts_are_written_only_when_they_change(db):
    from api.core import finding_history as fh
    from api.models.finding_history import DeviceDailyCount
    from api.models.vuln import Finding, FindingStatus
    tag = uuid.uuid4().hex[:6]
    d, src, _ = await _seed(db, tag)
    today = NOW.date()
    try:
        await fh.snapshot_devices(db, today - timedelta(days=2))
        mine = select(DeviceDailyCount).where(DeviceDailyCount.device_id == d.id)
        assert [(r.open, r.critical, r.high) for r in (await db.execute(mine)).scalars()] == [(1, 0, 0)]
        await fh.snapshot_devices(db, today - timedelta(days=1))                      # nothing changed: no row
        assert len((await db.execute(mine)).scalars().all()) == 1
        f = (await db.execute(select(Finding).where(Finding.source == src, Finding.status == FindingStatus.open))).scalar_one()
        f.status = FindingStatus.remediated
        await db.commit()
        await fh.snapshot_devices(db, today)                                           # fixed: a zero row
        assert [(r.day, r.open) for r in (await db.execute(mine.order_by(DeviceDailyCount.day))).scalars()][-1] == (today, 0)
        got = await fh.device_counts(db, str(d.id), today - timedelta(days=3), today)
        assert [o for o, _c, _h in got] == [0, 1, 1, 0]                               # carried across the quiet day
    finally:
        await db.execute(delete(DeviceDailyCount))
        await db.commit()


@pytest.mark.asyncio
async def test_old_score_history_keeps_one_entry_a_week(db):
    from api.core import finding_history as fh
    from api.models.risk import RiskScoreHistory as H
    e = str(uuid.uuid4())
    monday = (NOW - timedelta(days=400)).replace(hour=12, minute=0, second=0, microsecond=0)
    monday -= timedelta(days=monday.weekday())
    for i, score in enumerate((10.0, 20.0, 30.0)):                                     # Mon, Tue, Wed of one old week
        db.add(H(entity_type="device", entity_id=e, score=score, grade="C", recorded_at=monday + timedelta(days=i)))
    db.add(H(entity_type="device", entity_id=e, score=40.0, grade="C", recorded_at=NOW - timedelta(days=2)))
    db.add(H(entity_type="device", entity_id=e, score=50.0, grade="C", recorded_at=NOW - timedelta(days=1)))
    await db.commit()
    assert await fh.thin_score_history(db) >= 2
    await db.commit()
    left = (await db.execute(select(H.score).where(H.entity_id == e).order_by(H.recorded_at))).scalars().all()
    assert left == [30.0, 40.0, 50.0]                                                  # the week's last, and the recent ones


@pytest.mark.asyncio
async def test_retention_setting_takes_the_window(client_admin, client_cyber):
    r = (await client_admin.get("/api/v1/retention")).json()
    assert r["remediated_days"] == 90 and r["limits"]["remediated_days"] == [30, 365] and "remediated_due" in r
    body = {"enabled": True, "stale_host_days": r["stale_host_days"], "probe_within_days": r["probe_within_days"]}
    assert (await client_admin.put("/api/v1/retention", json={**body, "remediated_days": 10})).status_code == 422
    assert (await client_admin.put("/api/v1/retention", json={**body, "remediated_days": 120})).json()["remediated_days"] == 120
    assert (await client_cyber.put("/api/v1/retention", json={**body, "remediated_days": 120})).status_code == 403
    assert (await client_admin.put("/api/v1/retention", json={**body, "remediated_days": 90})).status_code == 200


def test_views_narrowed_past_what_the_rollup_records_get_none():
    from api.core.finding_history import roll_for
    assert roll_for() is not None and roll_for("rapid7_insightvm", kind="infra").sources == ("rapid7_insightvm",)
    assert roll_for(device_type="server") is None and roll_for(scope=object()) is None
    assert roll_for(code={"repo": "acme/app"}) is None and roll_for(code={"repo": None}) is not None
    assert roll_for(severity="critical_high").severities == ("critical", "high")
