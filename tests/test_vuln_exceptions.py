"""Vulnerability exceptions: who can do what, what an exception covers, and that it ends on time."""
from __future__ import annotations

import uuid
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from api.core import vuln_exceptions as vx
from api.models.vuln import ExceptionStatus, Finding, FindingStatus, VulnException


def _later(days=30):
    return (date.today() + timedelta(days=days)).isoformat()


async def _setup(db, it_user=None, n=3):
    from api.models.device import Device, DeviceAssignment, DeviceType
    from api.models.vuln import Vulnerability
    tag = uuid.uuid4().hex[:6]
    vuln = Vulnerability(title=f"PHP {tag}", cve_id=f"CVE-2026-{uuid.uuid4().int % 90000 + 10000}",
                         source="rapid7_insightvm", cvss_base=9.8)
    devs = [Device(hostname=f"ex-{tag}-{i}", device_type=DeviceType.workstation) for i in range(n)]
    db.add_all([vuln, *devs])
    await db.flush()
    db.add_all([Finding(device_id=d.id, vuln_id=vuln.id, source="rapid7_insightvm", source_id=f"a{i}:v{tag}")
                for i, d in enumerate(devs)])
    if it_user is not None:
        db.add(DeviceAssignment(device_id=devs[0].id, user_id=it_user.id))
    await db.commit()
    return vuln, devs


async def _statuses(db, vuln):
    rows = (await db.execute(select(Finding.status).where(Finding.vuln_id == vuln.id)
                             .execution_options(populate_existing=True))).scalars().all()
    return sorted(s.value for s in rows)


@pytest.mark.asyncio
async def test_cyber_exception_applies_at_once_and_revoke_restores(client_cyber, db):
    vuln, devs = await _setup(db)
    r = (await client_cyber.post("/api/v1/exceptions", json={
        "vuln_id": str(vuln.id), "scope": "devices", "device_ids": [str(devs[0].id), str(devs[1].id)],
        "reason": "Vendor patch due next quarter; app is internal only", "expires_on": _later()})).json()
    assert r["ok"] and r["status"] == "approved" and r["findings_covered"] == 2
    assert await _statuses(db, vuln) == ["open", "risk_accepted", "risk_accepted"]
    again = (await client_cyber.post("/api/v1/exceptions", json={
        "vuln_id": str(vuln.id), "scope": "finding", "device_ids": [str(devs[1].id)],
        "reason": "duplicate request here", "expires_on": _later()})).json()
    assert again["ok"] is False and "already" in again["error"]
    assert (await client_cyber.post(f"/api/v1/exceptions/{r['id']}/revoke", json={})).json()["ok"] is False  # note needed
    assert (await client_cyber.post(f"/api/v1/exceptions/{r['id']}/revoke", json={"note": "patched early"})).json()["ok"]
    assert await _statuses(db, vuln) == ["open", "open", "open"]


@pytest.mark.asyncio
async def test_it_user_requests_only_for_own_devices_and_sees_only_their_own(client_it_user, client_admin, it_user, db):
    vuln, devs = await _setup(db, it_user)
    body = {"vuln_id": str(vuln.id), "scope": "finding", "reason": "Kiosk app needs this PHP build",
            "expires_on": _later()}
    # a device they can't see: the same 404 as one that doesn't exist
    assert (await client_it_user.post("/api/v1/exceptions", json={**body, "device_ids": [str(devs[1].id)]})).status_code == 404
    assert (await client_it_user.post("/api/v1/exceptions", json={**body, "scope": "all"})).json()["ok"] is False
    r = (await client_it_user.post("/api/v1/exceptions", json={**body, "device_ids": [str(devs[0].id)]})).json()
    assert r["ok"] and r["status"] == "pending"
    assert await _statuses(db, vuln) == ["open", "open", "open"]   # nothing changes until approved
    # an IT user can't approve, and only sees their own requests
    assert (await client_it_user.post(f"/api/v1/exceptions/{r['id']}/approve", json={})).status_code == 404
    mine = (await client_it_user.get("/api/v1/exceptions", params={"tab": "all"})).json()
    assert {e["id"] for e in mine["exceptions"]} == {r["id"]} and mine["can_decide"] is False
    ok = (await client_admin.post(f"/api/v1/exceptions/{r['id']}/approve", json={"note": "fine for 30 days"})).json()
    assert ok["ok"] and ok["findings_covered"] == 1
    seen = (await client_it_user.get(f"/api/v1/exceptions/{r['id']}")).json()
    assert seen["status"] == "approved" and seen["decision_note"] == "fine for 30 days"
    assert await _statuses(db, vuln) == ["open", "open", "risk_accepted"]


@pytest.mark.asyncio
async def test_reject_needs_a_note_and_cancel_is_the_requesters(client_it_user, client_cyber, it_user, db):
    vuln, devs = await _setup(db, it_user)
    r = (await client_it_user.post("/api/v1/exceptions", json={
        "vuln_id": str(vuln.id), "scope": "finding", "device_ids": [str(devs[0].id)],
        "reason": "Needed for the label printer", "expires_on": _later()})).json()
    assert (await client_cyber.post(f"/api/v1/exceptions/{r['id']}/cancel", json={})).status_code == 404
    assert (await client_cyber.post(f"/api/v1/exceptions/{r['id']}/reject", json={})).json()["ok"] is False
    assert (await client_cyber.post(f"/api/v1/exceptions/{r['id']}/reject", json={"note": "patch is available"})).json()["ok"]
    got = (await client_it_user.get("/api/v1/exceptions", params={"tab": "rejected"})).json()["exceptions"]
    assert [e["status"] for e in got] == ["rejected"]


@pytest.mark.asyncio
async def test_all_scope_covers_new_findings_and_expiry_releases(client_admin, db):
    from api.models.device import Device, DeviceType
    vuln, devs = await _setup(db, n=2)
    r = (await client_admin.post("/api/v1/exceptions", json={
        "vuln_id": str(vuln.id), "scope": "all", "reason": "False positive: backported fix", "expires_on": _later(1)})).json()
    assert r["findings_covered"] == 2
    late = Device(hostname=f"late-{uuid.uuid4().hex[:6]}", device_type=DeviceType.server)
    db.add(late)
    await db.flush()
    db.add(Finding(device_id=late.id, vuln_id=vuln.id, source="rapid7_insightvm"))
    await db.commit()
    await vx.sync_all(db)        # what runs after every sync
    assert await _statuses(db, vuln) == ["risk_accepted"] * 3
    exc = await db.get(VulnException, r["id"])
    exc.expires_at = vx.now() - timedelta(minutes=1)
    await db.commit()
    await vx.sync_all(db)
    st = (await db.execute(select(VulnException.status).where(VulnException.id == r["id"]))).scalar_one()
    assert st == ExceptionStatus.expired
    assert await _statuses(db, vuln) == ["open"] * 3


@pytest.mark.parametrize("change", [
    {"expires_on": (date.today() + timedelta(days=400)).isoformat()},
    {"expires_on": date.today().isoformat()},
    {"reason": "short"},
    {"reason": "<script>alert(1)</script> long enough"},
    {"scope": "finding", "device_ids": []},
    {"scope": "tag"},
])
@pytest.mark.asyncio
async def test_bad_requests_are_refused(client_admin, change):
    body = {"vuln_id": str(uuid.uuid4()), "scope": "all", "reason": "a perfectly good reason", "expires_on": _later()}
    assert (await client_admin.post("/api/v1/exceptions", json={**body, **change})).status_code == 422


@pytest.mark.asyncio
async def test_roles_without_access_get_404(client_read_only):
    assert (await client_read_only.get("/api/v1/exceptions")).status_code == 404


@pytest.mark.asyncio
async def test_proof_checks_device_access_and_explains_non_rapid7(client_it_user, client_admin, it_user, db):
    vuln, devs = await _setup(db, it_user)
    fs = {str(f.device_id): str(f.id) for f in (await db.execute(select(Finding).where(Finding.vuln_id == vuln.id))).scalars()}
    assert (await client_it_user.get(f"/api/v1/findings/{fs[str(devs[1].id)]}/proof")).status_code == 404
    f = await db.get(Finding, fs[str(devs[0].id)])
    f.source = "qualys"
    await db.commit()
    out = (await client_it_user.get(f"/api/v1/findings/{fs[str(devs[0].id)]}/proof")).json()
    assert out["available"] is False and "Rapid7" in out["reason"]


def test_proof_html_becomes_plain_text():
    from api.core.finding_proof import as_text
    t = as_text("<p><p>Vulnerable software installed: PHP 8.5.1 (C:\\php\\php.exe)</p><ul><li>a &amp; b</li>"
                "<li><script>x</script>c</li></ul></p>")
    assert "Vulnerable software installed: PHP 8.5.1 (C:\\php\\php.exe)" in t and "- a & b" in t
    assert "<" not in t and as_text("") is None and as_text(None) is None
