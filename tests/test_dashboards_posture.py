"""Posture widgets: domain scorecards with counts and ages, control check compliance, host reporting coverage,
the priority action queue and the vulnerability age number."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.dashboards import catalog as cat

cat.load_metrics()
NOW = datetime.now(timezone.utc)


async def _seed(db):
    from api.core.device_tags import sync_tags
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    host = Device(hostname=f"srv-{n}", device_type=DeviceType.server, last_seen=NOW, edr_active=False, sources=",rapid7_insightvm,")
    repo = Device(hostname=f"acme/posture-{n}", device_type=DeviceType.code_repository, last_seen=NOW)
    db.add_all([host, repo])
    await db.flush()
    await sync_tags(db, host.id, {f"app:Posture{n}", f"tech_owner:pat{n}@acme.example"}, ("app:", "tech_owner:"), "manual", {})
    for i, (dev, dom, cvss, kev, age, key) in enumerate([(host, "infra", 9.8, True, 40, "x"), (host, "infra", 7.5, False, 10, "y"),
                                                         (repo, "code", 8.0, False, 100, "credential:1")]):
        v = Vulnerability(source="test", source_vuln_id=f"{key}-{n}-{i}", title=f"Posture flaw {n} {i}", cvss_base=cvss, is_kev=kev, domain=dom)
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=dev.id, vuln_id=v.id, source="rapid7_insightvm" if dom == "infra" else "github_code_review",
                       domain=dom, first_detected=NOW - timedelta(days=age)))
    await db.commit()
    return n, host


async def _data(client, metric, **params):
    w = {"id": "w", "metric": metric, "viz": cat.VIZ_FOR[cat.REGISTRY[metric].shape][0], "params": params}
    r = (await client.post("/api/v1/dashboards/data", json={"widgets": [w]})).json()
    return r["data"]["w"]


@pytest.mark.asyncio
async def test_every_scorecard_area_has_rows_with_counts_and_ages(db, client_admin):
    await _seed(db)
    for area in ("vulnerabilities", "endpoint", "identity", "code", "web", "ownership"):
        d = await _data(client_admin, "posture.scorecard", area=area)
        assert "error" not in d, (area, d)
        assert d["columns"] == ["Metric", "Count", "Avg age", "Max age", "Source"] and d["rows"], area
        assert len(d["hrefs"]) == len(d["rows"]) and d["headline"]
    vul = await _data(client_admin, "posture.scorecard", area="vulnerabilities")
    crit = next(r for r in vul["rows"] if r[0] == "Critical/high vulnerabilities")
    assert crit[1]["v"] >= 2 and crit[1]["tone"] == "critical" and crit[3]
    code = await _data(client_admin, "posture.scorecard", area="code")
    secrets = next(r for r in code["rows"] if r[0] == "Credentials found in code")
    assert secrets[1]["v"] >= 1


@pytest.mark.asyncio
async def test_queue_age_number_coverage_and_compliance(db, client_admin):
    n, host = await _seed(db)
    q = await _data(client_admin, "vuln.action_queue", limit=25, severity="critical_high", type="infra", rows="finding")
    assert q["columns"][:3] == ["Severity", "Issue", "Asset"]
    mine = [r for r in q["rows"] if f"Posture flaw {n}" in r[1]]
    assert mine[0][0] == {"v": "Critical", "tone": "critical"} and "(KEV)" in mine[0][1]          # KEV first
    assert mine[0][3] == f"Posture{n}" and mine[0][4] == f"pat{n}@acme.example"                    # application and owner
    assert mine[0][5] == {"v": "40d", "tone": "critical"} and mine[0][6] == {"v": "Overdue", "tone": "critical"}
    a = await _data(client_admin, "vuln.age", measure="count", type="code", severity="critical_high")
    assert a["value"] >= 1 and "average age" in a["note"] and "oldest" in a["note"]
    assert (await _data(client_admin, "vuln.age", measure="max_age", type="code", severity="critical_high"))["value"] >= 100
    cov = await _data(client_admin, "assets.reporting", tool="scanner")
    assert cov["unit"] == "%" and "active hosts" in cov["note"]
    comp = await _data(client_admin, "grc.compliance")
    assert comp["unit"] == "%" and "control checks" in comp["note"]
    # tables export as plain values
    r = await client_admin.post("/api/v1/dashboards/export", json={"widget": {"id": "q", "metric": "vuln.action_queue", "viz": "table",
                                                                           "params": {"limit": 5, "type": "infra"}}})
    assert r.status_code == 200 and "'tone'" not in r.text and "{" not in r.text.splitlines()[1]


@pytest.mark.asyncio
async def test_new_widgets_follow_the_viewers_access(db, client_it_user):
    await _seed(db)
    q = await _data(client_it_user, "vuln.action_queue", limit=25, type="any")
    assert q["rows"] == []                                       # nothing granted to this person
    d = await _data(client_it_user, "posture.scorecard", area="vulnerabilities")
    assert all((r[1]["v"] if isinstance(r[1], dict) else r[1]) == 0 for r in d["rows"])


@pytest.mark.asyncio
async def test_queue_shows_each_vulnerability_once_by_default(db, client_admin):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    v = Vulnerability(source="test", source_vuln_id=f"wide-{n}", title=f"Widespread {n}", cvss_base=10.0, is_kev=True)
    db.add(v)
    hosts = [Device(hostname=f"wide{i}-{n}", device_type=DeviceType.server, last_seen=NOW) for i in range(4)]
    db.add_all(hosts)
    await db.flush()
    for i, h in enumerate(hosts):
        db.add(Finding(device_id=h.id, vuln_id=v.id, source="test", first_detected=NOW - timedelta(days=10 + i)))
    await db.commit()
    q = await _data(client_admin, "vuln.action_queue", limit=25, type="any")
    mine = [r for r in q["rows"] if f"Widespread {n}" in r[1]]
    assert len(mine) == 1 and mine[0][2].endswith("(+3 more)") and mine[0][5]["v"] == "13d"   # its oldest asset
    each = await _data(client_admin, "vuln.action_queue", limit=25, type="any", rows="finding")
    assert len([r for r in each["rows"] if f"Widespread {n}" in r[1]]) == 4
