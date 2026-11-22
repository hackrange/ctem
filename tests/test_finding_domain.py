"""Every finding and vulnerability has a type (Infrastructure, Code or Web app), set as it is written or filled in
later, and the Vulnerabilities list filters by it."""
from __future__ import annotations

import uuid

import pytest


@pytest.mark.asyncio
async def test_type_is_set_on_insert_from_the_source(db):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    d = Device(hostname=f"fd-{n}", device_type=DeviceType.server)
    db.add(d)
    await db.flush()
    rows = {}
    for src in ("rapid7_insightvm", "snyk", "rapid7_appsec"):
        v = Vulnerability(source=src, source_vuln_id=f"{src}-{n}", title=f"t {n}")
        db.add(v)
        await db.flush()
        f = Finding(device_id=d.id, vuln_id=v.id, source=src)
        db.add(f)
        rows[src] = (v, f)
    explicit = Vulnerability(source="github_code_review", source_vuln_id=f"dast:x{n}", title="x", domain="web")
    db.add(explicit)
    await db.commit()
    assert [rows[s][0].domain for s in ("rapid7_insightvm", "snyk", "rapid7_appsec")] == ["infra", "code", "web"]
    assert [rows[s][1].domain for s in ("rapid7_insightvm", "snyk", "rapid7_appsec")] == ["infra", "code", "web"]
    assert explicit.domain == "web"   # a type the connector set stays


@pytest.mark.asyncio
async def test_fill_brings_old_rows_in_line_and_the_list_filters_by_type(db, client_admin):
    from sqlalchemy import update

    from api.core.finding_domain import fill
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    d = Device(hostname=f"ff-{n}", device_type=DeviceType.code_repository)
    db.add(d)
    await db.flush()
    code = Vulnerability(source="github_code_review", source_vuln_id=f"code:GCR-{n}", title=f"sql {n}")
    web = Vulnerability(source="github_code_review", source_vuln_id=f"dast:git {n}", title=f"git {n}")
    db.add_all([code, web])
    await db.flush()
    db.add_all([Finding(device_id=d.id, vuln_id=code.id, source="github_code_review"),
                Finding(device_id=d.id, vuln_id=web.id, source="github_code_review")])
    await db.commit()
    # rows written before types existed read as infrastructure
    await db.execute(update(Vulnerability).where(Vulnerability.id.in_([code.id, web.id])).values(domain="infra"))
    await db.execute(update(Finding).where(Finding.device_id == d.id).values(domain="infra"))
    await db.commit()
    assert await fill(db) >= 4
    await db.refresh(code)
    await db.refresh(web)
    assert (code.domain, web.domain) == ("code", "web")
    titles = lambda r: {v["title"] for v in r.json()["vulns"]}  # noqa: E731
    assert titles(await client_admin.get("/api/v1/vulns", params={"q": n, "type": "code"})) == {f"sql {n}"}
    assert titles(await client_admin.get("/api/v1/vulns", params={"q": n, "type": "web"})) == {f"git {n}"}
    assert titles(await client_admin.get("/api/v1/vulns", params={"q": n})) == {f"sql {n}", f"git {n}"}
    assert (await client_admin.get("/api/v1/vulns", params={"type": "app"})).status_code == 422
    r = (await client_admin.get("/api/v1/vulns", params={"q": n, "type": "code"})).json()["vulns"][0]
    assert r["domain"] == "code"



@pytest.mark.asyncio
async def test_hosts_repositories_and_sites_are_counted_apart(db, client_admin):
    from api.models.device import Device, DeviceType, RiskGrade
    n = uuid.uuid4().hex[:6]
    db.add_all([Device(hostname=f"h-{n}", device_type=DeviceType.server, risk_grade=RiskGrade.F),
                Device(hostname=f"acme/r-{n}", device_type=DeviceType.code_repository, risk_grade=RiskGrade.F, is_internet_exposed=True),
                Device(hostname=f"s-{n}.acme.example", device_type=DeviceType.website, is_internet_exposed=True)])
    await db.commit()
    names = lambda r: sorted(d["hostname"] for d in r.json()["devices"])  # noqa: E731
    assert names(await client_admin.get("/api/v1/devices", params={"q": n, "asset": "hosts"})) == [f"H-{n}".upper()]
    assert names(await client_admin.get("/api/v1/devices", params={"q": n, "asset": "repositories"})) == [f"acme/r-{n}"]
    assert names(await client_admin.get("/api/v1/devices", params={"q": n, "asset": "sites"})) == [f"s-{n}.acme.example"]
    assert len(names(await client_admin.get("/api/v1/devices", params={"q": n}))) == 3
    s = (await client_admin.get("/api/v1/devices/summary", params={"q": n, "asset": "repositories", "by": "application"})).json()
    assert s["total"] == 1 and s["grades"]["F"] == 1 and s["internet_exposed"] == 1 and s["by"] == "application"
    assert (await client_admin.get("/api/v1/devices", params={"asset": "printers"})).status_code == 422
    assert (await client_admin.get("/api/v1/devices/summary", params={"by": "password"})).status_code == 422
