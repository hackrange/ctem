"""The vulnerability dashboard's Risk grade view: open findings counted by risk grade, and each grade card opens
the vulnerability list filtered to that grade, within what the viewer may see."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select


@pytest.mark.asyncio
async def test_grades_counted_and_listed(db, client_admin):
    from api.core import vuln_dashboard as vd
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    t = uuid.uuid4().hex[:8]
    vs = [Vulnerability(source="rapid7_insightvm", source_vuln_id=f"g{i}-{t}", title=f"grade flaw {i} {t}", cvss_base=7.0)
          for i in range(3)]
    hosts = [Device(hostname=f"g{i}-{t}", device_type=DeviceType.server) for i in range(2)]
    db.add_all(vs + hosts)
    await db.flush()
    for h in hosts:
        db.add(Finding(device_id=h.id, vuln_id=vs[0].id, source="rapid7_insightvm", risk_grade="F"))
        db.add(Finding(device_id=h.id, vuln_id=vs[1].id, source="rapid7_insightvm", risk_grade="B"))
    db.add(Finding(device_id=hosts[0].id, vuln_id=vs[2].id, source="rapid7_insightvm", risk_grade="F",
                   status=FindingStatus.remediated))   # fixed: not counted
    await db.commit()
    w = vd._where(None, None, "infra") + [Finding.device_id.in_([h.id for h in hosts])]
    g = (await vd._units(db, w))["grades"]
    assert g == {"F": 2, "D": 0, "C": 0, "B": 2, "A": 0}
    r = (await client_admin.get("/api/v1/vulns", params={"grade": "F", "q": "grade flaw", "limit": 200})).json()
    mine = [v["title"] for v in r["vulns"] if v["title"].endswith(t)]
    assert mine == [f"grade flaw 0 {t}"]   # the resolved F finding doesn't put flaw 2 in the list
    assert (await client_admin.get("/api/v1/vulns", params={"grade": "E"})).status_code == 422
    assert (await client_admin.get("/api/v1/vulns/export", params={"grade": "F'--"})).status_code == 422
    assert (await db.execute(select(Finding).where(Finding.vuln_id == vs[0].id))).scalars().all()
