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
    assert len(vd._where("'; drop table findings; --", "nope")) == 1   # only the built-in "counts" condition
    assert len(vd._where("rapid7_insightvm", "server")) == 3


@pytest.mark.asyncio
async def test_only_fleet_wide_roles_see_it(client_it_user, client_admin, monkeypatch):
    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None, kind="all"):
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

    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None, kind="all"):
        seen["scope"] = scope
        return {"kpis": {}, "trend": {}}
    monkeypatch.setattr(vd, "cached", fake)
    r = (await client_read_only.get("/api/v1/vuln-dashboard")).json()
    assert r["scoped"] is True and seen["scope"] is not None


@pytest.mark.asyncio
async def test_source_lists_show_only_tools_this_install_uses(db, client_admin, monkeypatch):
    """Not every supported tool: a configured integration (enabled or not), or one with open findings left."""
    from api.core import vuln_dashboard as vd
    from api.models.integration import IntegrationConfig, Vendor

    async def fake(db, range_key, source, device_type, **kw):   # the trend query is Postgres-only
        return {"by_source": [{"source": "tenable", "open": 3}]}
    monkeypatch.setattr(vd, "cached", fake)
    db.add(IntegrationConfig(vendor=Vendor.qualys, name="Qualys", is_enabled=False, config={}))
    await db.commit()
    srcs = (await client_admin.get("/api/v1/vuln-dashboard")).json()["filters"]["sources"]
    assert "qualys" in srcs and "tenable" in srcs and "snyk" not in srcs   # tenable: findings left behind
    cat = (await client_admin.get("/api/v1/dashboards/catalog")).json()["metrics"]
    picker = next(p for m in cat if m["id"] == "vuln.kpi" for p in m["params"] if p["key"] == "source")
    values = [c["value"] for c in picker["choices"]]
    assert values[0] == "any" and "qualys" in values and "snyk" not in values



def test_the_three_types_split_the_findings():
    from sqlalchemy.dialects import postgresql
    from api.core import vuln_dashboard as vd
    sql = lambda kind: " ".join(str(c.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))  # noqa: E731
                                for c in vd._where(None, None, kind))
    for k in ("infra", "code", "web"):
        assert f"findings.domain = '{k}'" in sql(k)
    assert "domain" not in sql("all")


@pytest.mark.asyncio
async def test_dashboard_defaults_to_infrastructure_and_lists_sources_by_type(db, client_admin, monkeypatch):
    from api.core import vuln_dashboard as vd
    from api.models.integration import IntegrationConfig, Vendor
    db.add_all([IntegrationConfig(vendor=Vendor.github_code_review, name="GCR", is_enabled=True, config={}),
                IntegrationConfig(vendor=Vendor.rapid7_appsec, name="AppSec", is_enabled=True, config={}),
                IntegrationConfig(vendor=Vendor.rapid7_insightvm, name="IVM", is_enabled=True, config={})])
    await db.commit()
    seen = []

    async def fake(db, range_key, source, device_type, **kw):
        seen.append(kw.get("kind"))
        return {"by_source": []}
    monkeypatch.setattr(vd, "cached", fake)
    r = (await client_admin.get("/api/v1/vuln-dashboard")).json()
    by = r["filters"]["by_type"]
    assert r["kind"] == "infra" and "rapid7_insightvm" in by["infra"]
    assert "github_code_review" in by["code"] and "github_code_review" in by["web"] and "rapid7_appsec" in by["web"]
    assert "github_code_review" not in by["infra"]
    for k in ("code", "web"):
        await client_admin.get("/api/v1/vuln-dashboard", params={"kind": k})
    assert seen == ["infra", "code", "web"]
    assert (await client_admin.get("/api/v1/vuln-dashboard", params={"kind": "app"})).status_code == 422
