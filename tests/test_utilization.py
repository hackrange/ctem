"""Admin > Utilization: readers, trend, recording and rollup, admin-only API."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from api.core import utilization as ut


def test_proc_readers():
    a = ut.parse_stat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\n")
    b = ut.parse_stat("cpu  150 0 150 900 0 0 0 0 0 0\n")
    assert a == (1000, 800) and ut.cpu_percent(a, b) == 50.0
    assert ut.parse_stat("garbage") is None and ut.cpu_percent(None, b) is None
    used, total = ut.parse_meminfo("MemTotal:  1000 kB\nMemFree: 100 kB\nMemAvailable:  250 kB\n")
    assert (used, total) == (750 * 1024, 1000 * 1024)
    assert ut.parse_meminfo("MemTotal: x kB") is None
    du, dt = ut.disk("/")
    assert dt > 0 and 0 <= du <= dt


def test_days_until_full():
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    gb = 1024 ** 3
    pts = [{"t": (t0 + timedelta(hours=h)).isoformat(), "disk_used": 300 * gb + h * gb, "disk_total": 400 * gb}
           for h in range(24)]
    assert ut.days_until_full(pts) == pytest.approx((400 - 323) / 24, rel=0.01)   # 1 GB an hour, 77 GB left
    flat = [{**p, "disk_used": 300 * gb} for p in pts]
    assert ut.days_until_full(flat) is None and ut.days_until_full(pts[:3]) is None


@pytest.mark.asyncio
async def test_record_and_rollup(db, monkeypatch):
    from api.models.utilization import UtilSample
    monkeypatch.setattr(ut, "sample", lambda window=0.5: {"cpu": 40.0, "mem_used": 2, "mem_total": 8, "disk_used": 5,
                                                          "disk_total": 10, "cpus": 4})

    async def no_redis():
        return 123, None
    monkeypatch.setattr(ut, "redis_bytes", no_redis)
    await ut.record(db)
    rows = (await db.execute(select(UtilSample))).scalars().all()
    assert {r.tier for r in rows} == {"m", "h"}
    m = next(r for r in rows if r.tier == "m")
    assert (m.host_cpu, m.disk_used, m.redis_bytes) == (40.0, 5, 123)
    h = await ut.history(db, "24h")
    assert h["points"] and h["points"][-1]["cpu"] == 40.0


@pytest.mark.asyncio
async def test_admin_only(client_admin, client_cyber, client_read_only):
    for c in (client_cyber, client_read_only):
        assert (await c.get("/api/v1/admin/utilization/live")).status_code == 403
        assert (await c.get("/api/v1/admin/utilization/storage")).status_code == 403
    s = (await client_admin.get("/api/v1/admin/utilization/live")).json()
    assert s["disk_total"] > 0 and "cpu" in s
    st = (await client_admin.get("/api/v1/admin/utilization/storage")).json()
    assert st["disk"]["total"] > 0 and "tables" in st["database"]
    assert (await client_admin.get("/api/v1/admin/utilization/history", params={"range": "bogus"})).status_code == 422
