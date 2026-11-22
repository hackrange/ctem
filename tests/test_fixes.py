"""Fixes: findings grouped by the patch, upgrade or rollup that resolves them."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from api.core import fixes


def test_steps_are_plain_text_with_safe_links_only():
    text, links = fixes.plain('<p>Download from <a href="https://vendor.example/jre">here</a></p>'
                              '<script>alert(1)</script><a href="javascript:alert(1)">x</a><ul><li>Restart</li></ul>')
    assert "<" not in text and "Download from here" in text and "Restart" in text
    assert links == ["https://vendor.example/jre"]
    assert fixes.plain(None) == (None, [])


def test_keys_are_plain_identifiers():
    assert fixes.key("rapid7_insightvm", "jre-upgrade-latest") == "rapid7_insightvm:jre-upgrade-latest"
    assert fixes.key("rapid7_insightvm", "bad id; drop") is None and fixes.key("x", None) is None


def test_one_upgrade_per_package():
    k, fx = fixes.package_fix("github_code_review", {"name": "lodash", "fixed_in": "4.17.21", "ecosystem": "npm"})
    assert k == "github_code_review:pkg:npm:lodash" and fx["title"] == "Upgrade lodash to 4.17.21 or later"
    assert fixes.package_fix("github_code_review", {"name": "lodash"}) == (None, None)   # no fixed version, no fix


@pytest.mark.asyncio
async def test_insightvm_findings_carry_their_fix(db):
    from api.integrations.rapid7_insightvm import InsightVMConnector
    from api.models.vuln import Finding, Fix, Vulnerability
    t = uuid.uuid4().hex[:8]
    v1 = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"jre-1-{t}", title="Java flaw 1", cvss_base=9.8)
    v2 = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"jre-2-{t}", title="Java flaw 2", cvss_base=7.5)
    db.add_all([v1, v2])
    await db.commit()
    ids = {f"jre-1-{t}": str(v1.id), f"jre-2-{t}": str(v2.id)}
    sol = {"solution_id": f"jre-upgrade-{t}", "solution_summary": "Upgrade to the latest version of Oracle Java",
           "solution_type": "rollup", "solution_fix": '<p>Get it <a href="https://vendor.example/java">here</a></p>'}
    asset = {"id": f"a-{t}", "host_name": f"h-{t}.acme.example", "ip": "192.0.2.20",
             "same": [{"vulnerability_id": f"jre-1-{t}", **sol}, {"vulnerability_id": f"jre-2-{t}", **sol}]}
    await InsightVMConnector({"api_key": "k"})._upsert_cloud([asset], ids, db)
    got = (await db.execute(select(Finding.fix_key).where(Finding.vuln_id.in_(ids.values())))).scalars().all()
    assert got == [f"rapid7_insightvm:jre-upgrade-{t}"] * 2
    fx = (await db.execute(select(Fix).where(Fix.key == f"rapid7_insightvm:jre-upgrade-{t}"))).scalar_one()
    assert fx.kind == "rollup" and fx.title.startswith("Upgrade to the latest") and fx.links == ["https://vendor.example/java"]
    assert "<" not in fx.steps


async def _seed(db, t, n_hosts=3):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Fix, Vulnerability
    vs = [Vulnerability(source="rapid7_insightvm", source_vuln_id=f"v{i}-{t}", title=f"flaw {i} {t}", cvss_base=c, is_kev=k)
          for i, (c, k) in enumerate(((9.8, True), (7.5, False), (5.0, False)))]
    db.add_all(vs)
    hosts = [Device(hostname=f"h{i}-{t}", device_type=DeviceType.server) for i in range(n_hosts)]
    db.add_all(hosts)
    db.add(Fix(key=f"rapid7_insightvm:big-{t}", source="rapid7_insightvm", title=f"Big rollup {t}", kind="rollup"))
    await db.flush()
    for h in hosts:
        for v in vs[:2]:
            db.add(Finding(device_id=h.id, vuln_id=v.id, source="rapid7_insightvm", fix_key=f"rapid7_insightvm:big-{t}"))
        db.add(Finding(device_id=h.id, vuln_id=vs[2].id, source="rapid7_insightvm", fix_key=f"rapid7_insightvm:small-{t}"))
    await db.commit()
    return hosts, vs


@pytest.mark.asyncio
async def test_dashboard_counts_unique_vulnerabilities_and_fixes(db):
    from api.core import vuln_dashboard as vd
    from api.models.vuln import Finding
    t = uuid.uuid4().hex[:8]
    hosts, _ = await _seed(db, t)
    w = vd._where(None, None, "infra") + [Finding.device_id.in_([h.id for h in hosts])]
    u = await vd._units(db, w)
    assert u["vulns"]["open"] == 3 and u["vulns"]["critical"] == 1 and u["vulns"]["kev"] == 1
    assert u["fixes"]["open"] == 2 and u["fixes"]["critical"] == 1 and u["fixes"]["kev"] == 1 and u["fixes"]["medium"] == 1
    top = u["top_fixes"][0]
    assert top["title"] == f"Big rollup {t}" and (top["vulns"], top["devices"], top["findings"], top["critical"]) == (2, 3, 6, 3)


@pytest.mark.asyncio
async def test_fixes_api_ranks_filters_and_scopes(db, client_admin, client_it_user, monkeypatch):
    import api.routes.fixes as fr
    from api.core import vuln_dashboard as vd
    from api.models.vuln import Finding
    t = uuid.uuid4().hex[:8]
    hosts, vs = await _seed(db, t)
    mine = [h.id for h in hosts]
    # only this test's rows, and no Redis in tests
    real = vd._where
    monkeypatch.setattr(vd, "_where", lambda s, d, k="all": real(s, d, k) + [Finding.device_id.in_(mine)])

    class NoRedis:
        async def get(self, k):
            return None

        async def set(self, *a, **k):
            return True

        async def aclose(self):
            pass
    import redis.asyncio as aioredis
    monkeypatch.setattr(aioredis, "from_url", lambda *a, **k: NoRedis())
    d = (await client_admin.get("/api/v1/fixes", params={"kind": "infra"})).json()
    assert [f["title"] for f in d["fixes"]][:1] == [f"Big rollup {t}"] and d["total"] == 2 and d["findings_covered"] == 9
    assert (await client_admin.get("/api/v1/fixes", params={"severity": "kev"})).json()["total"] == 1
    assert (await client_admin.get("/api/v1/fixes", params={"q": "BIG ROLLUP"})).json()["total"] == 1
    assert (await client_admin.get("/api/v1/fixes", params={"sort": "nope; drop"})).status_code == 200   # unknown sort: risk
    one = (await client_admin.get("/api/v1/fixes/detail", params={"key": f"rapid7_insightvm:big-{t}"})).json()
    assert one["ok"] and one["devices"] == 3 and [v["cve_id"] for v in one["vulns"]] == [None, None] and one["vulns"][0]["kev"]
    assert (await client_admin.get("/api/v1/fixes/detail", params={"key": "<script>"})).status_code == 422
    assert (await client_admin.get("/api/v1/fixes/detail", params={"key": f"rapid7_insightvm:none-{t}"})).json()["ok"] is False
    assert (await client_it_user.get("/api/v1/fixes")).status_code == 404   # same viewers as the dashboard
    devs = (await client_admin.get("/api/v1/devices", params={"fix": f"rapid7_insightvm:big-{t}", "limit": 50})).json()["devices"]
    assert sorted(x["hostname"].lower() for x in devs) == sorted(h.hostname.lower() for h in hosts)
    assert (await client_admin.get("/api/v1/devices", params={"fix": "a b"})).status_code == 422
