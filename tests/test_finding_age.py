"""Age of vulnerabilities: days from first found until today (or until fixed), with the SLA for the severity."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.core import finding_age as age


def test_age_counts_to_today_or_to_the_fix():
    now = datetime.now(timezone.utc)
    a = age.view(now - timedelta(days=40), now, "open", 9.8)
    assert (a["age_days"], a["age_until"], a["sla_days"], a["past_sla"]) == (40, "today", 15, True)
    b = age.view(now - timedelta(days=40), now - timedelta(days=30), "remediated", 9.8)
    assert (b["age_days"], b["age_until"], b["past_sla"]) == (10, "fixed", False)
    assert age.view(now - timedelta(days=10), None, "open", 5.0)["past_sla"] is False   # medium: 90 days
    assert age.view(None, None, "open", 9.0)["age_days"] is None
    assert age.days(datetime(2026, 1, 1)) is not None   # naive timestamps (sqlite) count as UTC


async def _seed(db, n):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    now = datetime.now(timezone.utc)
    old = Vulnerability(source="test", source_vuln_id=f"old-{n}", title=f"old {n}", cvss_base=9.8, domain="infra")
    new = Vulnerability(source="test", source_vuln_id=f"new-{n}", title=f"new {n}", cvss_base=9.8, domain="code")
    db.add_all([old, new])
    h1, h2 = Device(hostname=f"age1-{n}", device_type=DeviceType.server), Device(hostname=f"age2-{n}", device_type=DeviceType.code_repository)
    db.add_all([h1, h2])
    await db.flush()
    db.add_all([Finding(device_id=h1.id, vuln_id=old.id, source="test", first_detected=now - timedelta(days=200)),
                Finding(device_id=h2.id, vuln_id=old.id, source="test", first_detected=now - timedelta(days=20)),
                Finding(device_id=h2.id, vuln_id=new.id, source="test", domain="code", first_detected=now - timedelta(days=3))])
    await db.commit()
    from api.scoring.engine import refresh_affected_counts
    await refresh_affected_counts(db)
    return old, new, h1


@pytest.mark.asyncio
async def test_lists_show_sort_and_filter_by_age(db, client_admin):
    n = uuid.uuid4().hex[:6]
    old, new, h1 = await _seed(db, n)
    rows = (await client_admin.get("/api/v1/vulns", params={"q": n, "sort": "age", "order": "desc"})).json()["vulns"]
    assert [r["title"] for r in rows] == [f"old {n}", f"new {n}"]
    assert rows[0]["age_days"] == 200 and rows[0]["past_sla"] and rows[1]["age_days"] == 3 and not rows[1]["past_sla"]
    assert [r["title"] for r in (await client_admin.get("/api/v1/vulns", params={"q": n, "min_age_days": 30})).json()["vulns"]] == [f"old {n}"]
    assert (await client_admin.get("/api/v1/vulns", params={"min_age_days": -1})).status_code == 422
    aff = (await client_admin.get(f"/api/v1/vulns/{old.id}/findings", params={"sort": "age", "order": "desc"})).json()["findings"]
    assert [f["age_days"] for f in aff] == [200, 20]
    one = (await client_admin.get(f"/api/v1/vulns/{old.id}")).json()
    assert one["age_days"] == 200 and one["first_found"]
    mine = (await client_admin.get(f"/api/v1/devices/{h1.id}/findings")).json()["findings"]
    assert mine[0]["age_days"] == 200 and mine[0]["sla_days"] == 15
    csv = (await client_admin.get("/api/v1/vulns/export", params={"q": n})).text
    assert "Age (days)" in csv.splitlines()[0] and ',"200","yes",' in csv


@pytest.mark.asyncio
async def test_a_finding_with_no_first_found_ages_from_when_ctem_stored_it(db):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    v = Vulnerability(source="test", source_vuln_id=f"nf-{n}", title="x", cvss_base=5.0)
    d = Device(hostname=f"nf-{n}", device_type=DeviceType.server)
    db.add_all([v, d])
    await db.flush()
    f = Finding(device_id=d.id, vuln_id=v.id, source="test")
    db.add(f)
    await db.commit()
    assert f.first_detected is not None and age.days(f.first_detected) == 0
