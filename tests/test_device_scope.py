"""Not In Scope: admin or cyber, with a justification and an end date; nothing on the device counts until it ends."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import select


async def _device_with_kev(db):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    tag = uuid.uuid4().hex[:6]
    dev = Device(hostname=f"oos-{tag}", device_type=DeviceType.server, last_seen=datetime.now(timezone.utc))
    v = Vulnerability(cve_id=f"CVE-2026-{int(tag, 16) % 90000 + 10000}", title="Acme flaw", cvss_base=9.8, is_kev=True,
                      source="t_scope")
    db.add_all([dev, v])
    await db.flush()
    db.add(Finding(device_id=dev.id, vuln_id=v.id, source="t_scope", status=FindingStatus.open))
    await db.commit()
    from api.scoring.engine import recalculate_device, refresh_affected_counts
    await recalculate_device(dev, db)
    await db.commit()
    await refresh_affected_counts(db)
    return dev, v


def _future(days=30):
    return (date.today() + timedelta(days=days)).isoformat()


@pytest.mark.asyncio
async def test_cyber_marks_out_of_scope_and_nothing_counts(db, client_cyber, client_admin):
    from api.models.settings import AuditLog
    dev, v = await _device_with_kev(db)
    before = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert before["open_findings"] == 1 and before["risk_score"] > 0 and before["out_of_scope"] is None
    r = await client_cyber.put(f"/api/v1/devices/{dev.id}/scope",
                               json={"justification": "Lab box, decommission ticket ACME-123", "expires_on": _future()})
    assert r.status_code == 200 and r.json()["out_of_scope"]["by"]
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert d["out_of_scope"]["reason"].startswith("Lab box") and d["can_set_scope"] is True
    assert (d["open_findings"], d["kev_findings"], d["risk_score"], d["risk_grade"]) == (0, 0, 0.0, "A")
    assert d["raw_risk_score"] > 0   # the real score is kept for when it comes back
    await db.refresh(v)
    assert v.affected_devices == 0
    listed = (await client_admin.get("/api/v1/devices", params={"status": "out_of_scope", "q": dev.hostname})).json()
    assert listed["total"] == 1 and listed["devices"][0]["out_of_scope_until"]
    f = (await client_admin.get(f"/api/v1/devices/{dev.id}/findings")).json()
    assert f["contained"] is True and f["findings"][0]["severity"] == "info"   # shown, dimmed, not counted
    # Back in scope
    assert (await client_admin.delete(f"/api/v1/devices/{dev.id}/scope")).status_code == 204
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert d["out_of_scope"] is None and d["open_findings"] == 1 and d["risk_score"] > 0
    acts = (await db.execute(select(AuditLog.action).where(AuditLog.resource_id == str(dev.id)))).scalars().all()
    assert {"device.scope_out", "device.scope_in"} <= set(acts)


@pytest.mark.asyncio
async def test_only_admin_or_cyber_and_inputs_are_checked(db, client_cyber, client_it_user, client_read_only):
    dev, _ = await _device_with_kev(db)
    url, ok = f"/api/v1/devices/{dev.id}/scope", {"justification": "Vendor-managed appliance", "expires_on": _future()}
    assert (await client_it_user.put(url, json=ok)).status_code == 403
    assert (await client_read_only.put(url, json=ok)).status_code == 403
    assert (await client_read_only.delete(url)).status_code == 403
    for bad in ({**ok, "justification": "short"}, {**ok, "expires_on": date.today().isoformat()},
                {**ok, "expires_on": _future(400)}, {**ok, "justification": "<script>x</script> long enough"},
                {**ok, "extra": 1}, {"justification": ok["justification"]}):
        assert (await client_cyber.put(url, json=bad)).status_code == 422, bad
    assert (await client_cyber.put(f"/api/v1/devices/{uuid.uuid4()}/scope", json=ok)).status_code == 404
    assert (await client_cyber.get(f"/api/v1/devices/{dev.id}")).json()["out_of_scope"] is None


@pytest.mark.asyncio
async def test_an_ended_exclusion_clears_and_counts_again(db):
    from api.models.settings import AuditLog
    from api.scoring.engine import expire_scope_exemptions, recalculate_device
    dev, _ = await _device_with_kev(db)
    dev.scope_exempt_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    dev.scope_exempt_reason, dev.scope_exempt_by = "ended yesterday", "cyber"
    await db.commit()
    assert str(dev.id) in await expire_scope_exemptions(db)
    await db.refresh(dev)
    assert dev.scope_exempt_until is None and dev.scope_exempt_reason is None
    await recalculate_device(dev, db)
    assert dev.open_findings == 1
    acts = (await db.execute(select(AuditLog.action).where(AuditLog.resource_id == str(dev.id)))).scalars().all()
    assert "device.scope_expired" in acts
