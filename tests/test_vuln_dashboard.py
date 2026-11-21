"""Vulnerability dashboard: the trend arithmetic, range slicing, and who may see fleet-wide numbers."""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from api.core import vuln_dashboard as vd

TODAY = date(2026, 11, 20)


def test_open_is_new_minus_fixed_and_ends_at_today():
    d = lambda n: TODAY - timedelta(days=n)  # noqa: E731
    new = [(d(5), "critical", True, 10), (d(5), "high", False, 4), (d(2), "critical", False, 3)]
    fixed = [(d(3), "critical", True, 6), (d(1), "high", False, 4)]
    s = vd.series(new, fixed, TODAY, None)
    assert s["days"][0] == d(5).isoformat() and s["days"][-1] == TODAY.isoformat()
    # day -5: 10 critical (all KEV), 4 high; day -3: 6 KEV criticals fixed; day -2: 3 more; day -1: highs fixed
    assert s["critical"] == [10, 10, 4, 7, 7, 7]
    assert s["high"] == [4, 4, 4, 4, 0, 0]
    assert s["kev"] == [10, 10, 4, 4, 4, 4]
    assert s["new"] == [14, 0, 0, 3, 0, 0] and s["fixed"] == [0, 0, 6, 0, 4, 0]


def test_range_starts_from_the_running_total_not_zero():
    old = TODAY - timedelta(days=400)
    s = vd.series([(old, "medium", False, 50)], [(TODAY - timedelta(days=10), "medium", False, 20)], TODAY, 30)
    assert len(s["days"]) == 30 and s["medium"][0] == 50 and s["medium"][-1] == 30


def test_slice_cuts_every_series_to_the_range():
    full = vd.series([(TODAY - timedelta(days=200), "low", False, 1)], [], TODAY, None)
    out = vd.sliced({"trend": full, "kpis": {}}, "30d")
    assert all(len(v) == 30 for v in out["trend"].values()) and out["range"] == "30d"
    assert len(vd.sliced({"trend": full}, "all")["trend"]["days"]) == 201


def test_filters_are_allow_listed():
    assert vd._where("'; drop table findings; --", "nope") == []
    assert len(vd._where("rapid7_insightvm", "server")) == 2


@pytest.mark.asyncio
async def test_only_fleet_wide_roles_see_it(client_it_user, client_admin, monkeypatch):
    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None):
        return {"range": range_key, "kpis": {"open": 1}, "trend": {}, "source": source}
    monkeypatch.setattr(vd, "cached", fake)
    assert (await client_it_user.get("/api/v1/vuln-dashboard")).status_code == 404
    r = (await client_admin.get("/api/v1/vuln-dashboard", params={"range": "30d", "source": "rapid7_insightvm"})).json()
    assert r["range"] == "30d" and r["source"] == "rapid7_insightvm" and "server" in r["filters"]["device_types"]
    assert (await client_admin.get("/api/v1/vuln-dashboard", params={"source": "evil"})).status_code == 422
    assert (await client_admin.get("/api/v1/vuln-dashboard", params={"range": "7y"})).status_code == 422


@pytest.mark.asyncio
async def test_read_only_numbers_are_limited_to_their_devices(client_read_only, monkeypatch):
    seen = {}

    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None):
        seen["scope"] = scope
        return {"kpis": {}, "trend": {}}
    monkeypatch.setattr(vd, "cached", fake)
    r = (await client_read_only.get("/api/v1/vuln-dashboard")).json()
    assert r["scoped"] is True and seen["scope"] is not None
