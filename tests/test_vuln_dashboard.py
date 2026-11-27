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
async def test_fleet_wide_roles_see_everything_and_it_users_their_own(client_it_user, client_admin, monkeypatch):
    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None, kind="all", **kw):
        return {"range": range_key, "kpis": {"open": 1}, "trend": {}, "source": source}
    monkeypatch.setattr(vd, "cached", fake)
    assert (await client_it_user.get("/api/v1/vuln-dashboard")).json()["scoped"] is True   # their own assets only
    r = (await client_admin.get("/api/v1/vuln-dashboard", params={"range": "30d", "source": "rapid7_insightvm"})).json()
    assert r["range"] == "30d" and r["source"] == "rapid7_insightvm" and "server" in r["filters"]["device_types"]
    assert (await client_admin.get("/api/v1/vuln-dashboard", params={"source": "evil"})).status_code == 422
    assert (await client_admin.get("/api/v1/vuln-dashboard", params={"range": "7y"})).status_code == 422


@pytest.mark.asyncio
async def test_read_only_numbers_are_limited_to_their_devices(client_read_only, monkeypatch):
    seen = {}

    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None, kind="all", **kw):
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
    assert picker["type"] == "multi" and "any" not in values and "qualys" in values and "snyk" not in values



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


class _Redis:
    """Just enough Redis for the dashboard cache."""
    store: dict = {}

    async def get(self, k):
        return self.store.get(k)

    async def set(self, k, v, ex=None, nx=False):
        if nx and k in self.store:
            return None
        self.store[k] = v.encode() if isinstance(v, str) else v
        return True

    async def delete(self, k):
        return 1 if self.store.pop(k, None) is not None else 0

    async def exists(self, k):
        return int(k in self.store)

    async def scan_iter(self, match="*", count=None):
        import fnmatch
        for k in list(self.store):
            if fnmatch.fnmatch(k, match):
                yield k

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_after_a_sync_the_old_view_answers_at_once_and_rebuilds_in_the_background(monkeypatch):
    import redis.asyncio as aioredis
    _Redis.store = {}
    monkeypatch.setattr(aioredis, "from_url", lambda *a, **k: _Redis())
    builds, queued = [], []

    async def build(db, source, device_type, scope=None, kind="all", code=None):
        builds.append(kind)
        return {"generated_at": vd._now().isoformat(), "trend": {"days": []}, "n": len(builds)}
    monkeypatch.setattr(vd, "build", build)
    monkeypatch.setattr(vd, "_rebuild_later", lambda *a: queued.append(a))
    first = await vd.cached(None, "90d", None, None, kind="code")
    assert first["n"] == 1 and (await vd.cached(None, "90d", None, None, kind="code"))["n"] == 1   # cached
    _Redis.store["dashw:x"] = b"1"
    await vd.forget_cached()
    assert "dashw:x" not in _Redis.store
    vd_key = next(k for k in _Redis.store if k.startswith("vulndash:v5:code"))
    assert vd_key   # the view is kept, only marked out of date
    _Redis.store[vd.DIRTY_KEY] = str(vd._now().timestamp() + 1).encode()
    again = await vd.cached(None, "90d", None, None, kind="code")
    assert again["n"] == 1 and len(builds) == 1          # answered from the old view, nobody waited
    await vd.cached(None, "90d", None, None, kind="code")
    assert queued == [(None, None, "code", None, None)]  # rebuilt once, not once per visitor


@pytest.mark.asyncio
async def test_a_new_view_is_built_once_for_everyone_and_a_page_never_waits_long(monkeypatch):
    """A hundred people opening a view nobody built yet run one build; a page request gives up after `wait` (the page
    asks again) instead of being cut off by the proxy; an old build answers at once and is redone in the background."""
    import asyncio
    import json
    import redis.asyncio as aioredis
    from api.core import vuln_dashboard_cache as vc
    _Redis.store = {}
    monkeypatch.setattr(aioredis, "from_url", lambda *a, **k: _Redis())
    builds, queued, gate = [], [], asyncio.Event()

    async def build(db, source, device_type, scope=None, kind="all", code=None):
        builds.append(device_type)
        await gate.wait()
        return {"generated_at": vd._now().isoformat(), "trend": {"days": []}, "n": len(builds)}

    async def sessions():
        yield None
    monkeypatch.setattr(vd, "build", build)
    monkeypatch.setattr(vd, "_rebuild_later", lambda *a: queued.append(a))
    monkeypatch.setattr("api.core.db.get_session", sessions)
    assert await vd.cached(None, "90d", None, "workstation", kind="infra", wait=0.6) is None   # not ready: the page asks again
    waiting = [asyncio.create_task(vd.cached(None, "90d", None, "workstation", kind="infra", wait=10)) for _ in range(100)]
    await asyncio.sleep(0.1)
    gate.set()
    got = await asyncio.gather(*waiting)
    assert builds == ["workstation"] and all(g["n"] == 1 for g in got)   # one build, everyone got it
    key = next(k for k in _Redis.store if k.startswith("vulndash:v5:infra:-:workstation"))
    old = json.loads(_Redis.store[key])
    old["generated_at"] = (vd._now() - __import__("datetime").timedelta(seconds=vc.CACHE_SECONDS + 5)).isoformat()
    _Redis.store[key] = json.dumps(old).encode()
    assert (await vd.cached(None, "90d", None, "workstation", kind="infra", wait=10))["n"] == 1 and len(queued) == 1


@pytest.mark.asyncio
async def test_the_page_hears_202_while_its_view_is_built(client_admin, monkeypatch):
    async def building(*a, **k):
        assert k.get("wait") == vd.WAIT_SECONDS
        return None
    monkeypatch.setattr(vd, "cached", building)
    r = await client_admin.get("/api/v1/vuln-dashboard", params={"device_type": "workstation"})
    assert r.status_code == 202 and r.json() == {"building": True}


@pytest.mark.asyncio
async def test_host_device_type_is_ignored_on_code_and_web(client_admin, monkeypatch):
    seen = []

    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None, kind="all", **kw):
        seen.append((kind, device_type))
        return {"kpis": {}, "trend": {}}
    monkeypatch.setattr(vd, "cached", fake)
    for kind in ("infra", "code", "web"):
        await client_admin.get("/api/v1/vuln-dashboard", params={"kind": kind, "device_type": "server"})
    assert seen == [("infra", "server"), ("code", None), ("web", None)]


def test_code_filters_only_apply_on_the_code_tab():
    code = {"org": "acme", "repo": "acme/pay", "app_tags": ["app:Pay"]}
    assert len(vd._where(None, None, "code", code)) == 5   # counts, kind, repo, org, application
    assert len(vd._where(None, None, "infra", code)) == 2  # ignored off the Code tab
    sql = str(vd._where(None, None, "code", {"org": "a_b%"})[-1].compile(compile_kwargs={"literal_binds": True}))
    assert "a\\_b\\%/%" in sql   # the org's own _ and % are not wildcards


@pytest.mark.asyncio
async def test_code_filters_take_only_names_this_viewer_may_see(client_admin, monkeypatch):
    seen = []

    async def fake(db, range_key, source, device_type, fresh=False, scope=None, viewer=None, kind="all", **kw):
        seen.append(kw.get("code"))
        return {"kpis": {}, "trend": {}}

    async def opts(db, scope=None):
        return {"orgs": ["acme"], "repos": [{"name": "acme/pay", "org": "acme", "apps": ["Pay"]}],
                "apps": [{"value": "Pay", "tags": ["app:Pay", "r7:app:Pay"]}]}
    monkeypatch.setattr(vd, "cached", fake)
    monkeypatch.setattr(vd, "code_filters", opts)
    r = await client_admin.get("/api/v1/vuln-dashboard", params={"kind": "code", "org": "acme", "app": "Pay", "repo": "acme/pay"})
    assert r.status_code == 200 and r.json()["filters"]["code"]["repos"][0]["name"] == "acme/pay"
    assert seen[-1] == {"org": "acme", "repo": "acme/pay", "app_tags": ["app:Pay", "r7:app:Pay"]}
    for bad in ({"org": "other"}, {"repo": "other/x"}, {"app": "Nope"}):
        assert (await client_admin.get("/api/v1/vuln-dashboard", params={"kind": "code", **bad})).status_code == 422
    await client_admin.get("/api/v1/vuln-dashboard", params={"kind": "infra", "org": "whatever"})
    assert seen[-1] is None   # not read off the Code tab


def test_device_list_narrows_to_an_organization_or_repository():
    from api.routes import device_query as dq
    sql = " ".join(str(c.compile(compile_kwargs={"literal_binds": True}))
                   for c in dq.card_filters({"repo_org": "my_org", "repo": "my_org/pay"}))
    assert "my\\_org/%" in sql and "'my_org/pay'" in sql and "code_repository" in sql.lower()


@pytest.mark.asyncio
async def test_device_repo_filters_reject_anything_but_a_repository_name(client_admin):
    for bad in ({"repo_org": "a%"}, {"repo": "nope"}, {"repo": "a/b/../c"}):
        assert (await client_admin.get("/api/v1/devices", params=bad)).status_code == 422
