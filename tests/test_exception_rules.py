"""Rule exceptions: admin-only, dynamic (new matches covered, non-matches released), same rules as any exception."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from api.core import exception_rules as er


def _until(days=60):
    return (date.today() + timedelta(days=days)).isoformat()


def test_rule_validation():
    ok = er.parse({"schema": "open-ctem/exception-rule@1", "name": "Legacy gear",
                   "devices": {"include": {"hostname_patterns": ["can*"], "os_starts_with": ["Cisco IOS"]}},
                   "vulnerabilities": {"cve_ids": ["cve-2026-12345"], "kev": False}})
    assert ok.vulnerabilities.cve_ids == ["CVE-2026-12345"]
    text = er.describe(ok)
    assert text.startswith("Rule: Legacy gear (") and "hostname patterns can*" in text and "os starts with Cisco IOS" in text
    for bad in ({"name": "x", "devices": {"include": {"hostname_patterns": ["a"]}}},            # name too short
                {"name": "No devices", "devices": {}},                                         # include required
                {"name": "Exclude only", "devices": {"exclude": {"device_types": ["server"]}}},
                {"name": "Bad glob", "devices": {"include": {"hostname_patterns": ["can;drop"]}}},
                {"name": "Bad cve", "devices": {"include": {"device_types": ["server"]}}, "vulnerabilities": {"cve_ids": ["x"]}},
                {"name": "Range", "devices": {"include": {"device_types": ["server"]}},
                 "vulnerabilities": {"min_cvss": 9, "max_cvss": 3}},
                {"name": "Extra", "devices": {"include": {"device_types": ["server"]}}, "sql": "1=1"}):
        with pytest.raises(Exception):
            er.parse(bad)


async def _gear(db, n, name, os, kev=False):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    d = Device(hostname=f"{name}-{n}.ad.acme.example", os=os, device_type=DeviceType.network_device,
               last_seen=datetime.now(timezone.utc))
    v = Vulnerability(cve_id=f"CVE-2026-{uuid.uuid4().int % 90000 + 10000}", title=f"IOS flaw {n}", cvss_base=8.0,
                      is_kev=kev, source="t_exrule")
    db.add_all([d, v])
    await db.flush()
    db.add(Finding(device_id=d.id, vuln_id=v.id, source="rapid7_insightvm", status=FindingStatus.open))
    await db.commit()
    return d


def _rule(n):
    return {"schema": "open-ctem/exception-rule@1", "name": f"Legacy Cisco {n}",
            "devices": {"include": {"hostname_patterns": [f"can*{n}*"], "os_starts_with": ["Cisco IOS"]}}}


@pytest.mark.asyncio
async def test_admin_creates_a_dynamic_rule_exception(db, client_admin, client_cyber, client_it_user):
    from api.core.vuln_exceptions import sync_all
    from api.models.vuln import Finding, FindingStatus
    n = uuid.uuid4().hex[:6]
    sw1 = await _gear(db, n, "can-sw01", "Cisco IOS 15.2")
    other = await _gear(db, n, "nyc-sw01", "Cisco IOS 15.2")       # wrong name
    pc = await _gear(db, n, "can-pc01", "Windows 11")              # wrong OS
    body = {"rule": _rule(n), "reason": "End-of-life switches pending replacement",
            "compensating_controls": "Reachable only through the bastion; firewall allows two admin IPs",
            "expires_on": _until()}
    # Admin only (cyber and IT users can't even preview)
    for c in (client_cyber, client_it_user):
        assert (await c.post("/api/v1/exceptions/rule/preview", json={"rule": _rule(n)})).status_code == 403
        assert (await c.post("/api/v1/exceptions/rule", json=body)).status_code == 403
    p = (await client_admin.post("/api/v1/exceptions/rule/preview", json={"rule": _rule(n)})).json()
    assert p["ok"] and p["devices"] == 1 and p["open_findings"] == 1 and p["sample"] == [f"CAN-SW01-{n}".upper()]
    # Same rules as any exception: compensating controls required, a year at most
    assert (await client_admin.post("/api/v1/exceptions/rule", json={**body, "compensating_controls": ""})).status_code == 422
    assert (await client_admin.post("/api/v1/exceptions/rule", json={**body, "expires_on": _until(400)})).status_code == 422
    made = (await client_admin.post("/api/v1/exceptions/rule", json=body)).json()
    assert made["ok"] and made["findings_covered"] == 1 and made["devices"] == 1
    status = lambda d: db.execute(select(Finding.status).where(Finding.device_id == d.id)  # noqa: E731
                                  .execution_options(populate_existing=True))
    assert (await status(sw1)).scalar_one() == FindingStatus.risk_accepted
    assert (await status(other)).scalar_one() == FindingStatus.open and (await status(pc)).scalar_one() == FindingStatus.open
    # Dynamic: a new matching device is covered on the next sync; one that stops matching is released
    sw2 = await _gear(db, n, "can-sw02", "Cisco IOS XE 17")
    sw1.os = "Windows 11"
    await db.commit()
    await sync_all(db)
    assert (await status(sw2)).scalar_one() == FindingStatus.risk_accepted
    assert (await status(sw1)).scalar_one() == FindingStatus.open
    # Listed with its rule; revoking releases everything
    listed = (await client_admin.get("/api/v1/exceptions", params={"tab": "active", "q": f"Legacy Cisco {n}"})).json()
    row = listed["exceptions"][0]
    assert row["scope"] == "rule" and row["vuln_id"] is None and row["covers"].startswith(f"Rule: Legacy Cisco {n}")
    detail = (await client_admin.get(f"/api/v1/exceptions/{made['id']}")).json()
    assert detail["rule"]["devices"]["include"]["os_starts_with"] == ["Cisco IOS"]
    r = (await client_admin.post(f"/api/v1/exceptions/{made['id']}/revoke", json={"note": "Replaced"})).json()
    assert r["ok"] and (await status(sw2)).scalar_one() == FindingStatus.open


@pytest.mark.asyncio
async def test_too_broad_and_empty_rules_are_refused(db, client_admin, monkeypatch):
    n = uuid.uuid4().hex[:6]
    await _gear(db, n, "can-a", "Cisco IOS 12")
    await _gear(db, n, "can-b", "Cisco IOS 12")
    body = {"rule": _rule(n), "reason": "Old gear awaiting replacement", "compensating_controls": "Bastion and ACLs only",
            "expires_on": _until()}
    monkeypatch.setattr(er, "MAX_DEVICES", 1)
    r = (await client_admin.post("/api/v1/exceptions/rule", json=body)).json()
    assert r["ok"] is False and "at most 1" in r["error"]
    none = {**body, "rule": {**_rule(n), "devices": {"include": {"hostname_patterns": ["no-such-host-zz"]}}}}
    assert "matches no devices" in (await client_admin.post("/api/v1/exceptions/rule", json=none)).json()["error"]
    bad = (await client_admin.post("/api/v1/exceptions/rule/preview", json={"rule": {"name": "x"}})).json()
    assert bad["ok"] is False and bad["error"].startswith("The rule isn't valid")


@pytest.mark.asyncio
async def test_vulnerability_filter_leaves_kev_out(db, client_admin):
    n = uuid.uuid4().hex[:6]
    await _gear(db, n, "can-k1", "Cisco IOS 15", kev=True)
    await _gear(db, n, "can-k2", "Cisco IOS 15", kev=False)
    rule = {**_rule(n), "vulnerabilities": {"kev": False}}
    p = (await client_admin.post("/api/v1/exceptions/rule/preview", json={"rule": rule})).json()
    assert p["devices"] == 2 and p["open_findings"] == 1 and p["kev_findings"] == 0


@pytest.mark.asyncio
async def test_ai_draft_never_writes_the_reason(db, client_admin, monkeypatch):
    from api.core import exception_rules_ai as ai

    class Fake:
        async def complete(self, prompt, **kw):
            assert "can*" in prompt and "data from an admin" in prompt
            return ('{"schema": "open-ctem/exception-rule@1", "name": "Legacy Cisco gear", "reason": "trust me",'
                    ' "devices": {"include": {"hostname_patterns": ["can*"], "os_starts_with": ["Cisco IOS"]}},'
                    ' "note": "Assumed CAN is the start of the hostname."}')

    async def fake_ai(db):
        return Fake()
    monkeypatch.setattr("api.hunt.ai.get_ai", fake_ai)
    r = (await client_admin.post("/api/v1/exceptions/rule/draft", json={"text": "devices named CAN with Cisco IOS"})).json()
    assert r["document"]["name"] == "Legacy Cisco gear" and "reason" not in r["document"]
    assert r["note"].startswith("Assumed")


@pytest.mark.asyncio
async def test_preview_warns_how_many_hosts_it_excludes(db, client_admin, monkeypatch):
    n = uuid.uuid4().hex[:6]
    for i in range(3):
        await _gear(db, n, f"can-w{i}", "Cisco IOS 15")
    assert er.MAX_DEVICES == 100_000
    p = (await client_admin.post("/api/v1/exceptions/rule/preview", json={"rule": _rule(n)})).json()
    assert p["warning"] is None   # 3 hosts, no KEV
    monkeypatch.setattr(er, "WARN_DEVICES", 2)
    p = (await client_admin.post("/api/v1/exceptions/rule/preview", json={"rule": _rule(n)})).json()
    assert p["warning"].startswith("This exception will exclude 3 hosts (3 open findings")
