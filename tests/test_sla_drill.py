"""The SLA check's drill-down: findings and assets past SLA by kind of asset and by risk grade, and the lists it links
to (devices, fixes) filtered to findings past SLA."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

NOW = datetime.now(timezone.utc)


async def _breached(db, tag):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    v = Vulnerability(cve_id=f"CVE-2099-{uuid.uuid4().int % 90000 + 10000}", title=f"sla {tag}", cvss_base=9.8, source="qualys")
    ok = Vulnerability(cve_id=f"CVE-2099-{uuid.uuid4().int % 90000 + 10000}", title=f"fresh {tag}", cvss_base=9.8, source="qualys")
    devs = {k: Device(hostname=f"{tag}-{k.value}", device_type=k, last_seen=NOW)
            for k in (DeviceType.workstation, DeviceType.server, DeviceType.cloud_instance, DeviceType.code_repository)}
    db.add_all([v, ok, *devs.values()])
    await db.flush()
    for k, d in devs.items():
        db.add(Finding(device_id=d.id, vuln_id=v.id, source="qualys", status=FindingStatus.open, first_detected=NOW - timedelta(days=40),
                       risk_grade="F" if k == DeviceType.server else "C", fix_key=f"fix:{tag}"))
    db.add(Finding(device_id=devs[DeviceType.workstation].id, vuln_id=ok.id, source="qualys", status=FindingStatus.open,
                   first_detected=NOW - timedelta(days=2), fix_key=f"fresh:{tag}"))
    await db.commit()
    return devs, (v, ok)


@pytest.mark.asyncio
async def test_breakdown_by_asset_and_grade(db):
    from api.grc.checks.vulns import _sla_breakdown
    tag = f"sl{uuid.uuid4().hex[:6]}"
    t = {"critical_days": 15, "high_days": 30, "reachable_only": 0}
    before = await _sla_breakdown(db, t)
    await _breached(db, tag)
    after = await _sla_breakdown(db, t)
    diff = {a["kind"]: a["findings"] - b["findings"] for a, b in zip(after["by_asset"], before["by_asset"])}
    assert diff == {"workstation": 1, "server": 1, "network": 0, "cloud": 1, "code": 1, "web": 0, "unknown": 0}
    g = {a["grade"]: a["findings"] - b["findings"] for a, b in zip(after["by_grade"], before["by_grade"])}
    assert g["F"] == 1 and g["C"] == 3


@pytest.mark.asyncio
async def test_devices_and_fixes_filter_to_past_sla(db, client_admin):
    tag = f"sd{uuid.uuid4().hex[:6]}"
    devs, _ = await _breached(db, tag)
    names = {d["hostname"].lower() for d in (await client_admin.get("/api/v1/devices", params={"q": tag, "past_sla": "true", "limit": 200})).json()["devices"]}
    assert f"{tag}-workstation" in names and f"{tag}-server" in names
    fresh = await client_admin.get("/api/v1/devices", params={"q": tag, "past_sla": "true", "device_type": "server"})
    assert [d["hostname"].lower() for d in fresh.json()["devices"]] == [f"{tag}-server"]
    keys = {f["key"] for f in (await client_admin.get("/api/v1/fixes", params={"kind": "all", "past_sla": "true", "q": tag, "limit": 200})).json()["fixes"]}
    assert f"fix:{tag}" in keys and f"fresh:{tag}" not in keys   # a two-day-old finding isn't past its SLA
    from api.models.device import Device
    await db.execute(delete(Device).where(Device.hostname.like(f"{tag}-%")))
    await db.commit()
