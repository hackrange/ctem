"""Tanium: a read-only GET client, endpoints with their patch history and encryption, software, CVE findings with
proof that close when Tanium stops reporting them (never on "no results"), the Pull options, and the device tab."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select

SENS = [{"name": "Title", "sensor": {"name": "Patch Installation History"}, "values": ["2026-11 Cumulative Update", "Edge 142", "TSE-Error: x"]},
        {"name": "Date Installed", "sensor": {"name": "Patch Installation History"}, "values": ["2026-11-19", "2026-10-02", ""]},
        {"name": "Install Source", "sensor": {"name": "Patch Installation History"}, "values": ["Windows Update", "Tanium", ""]},
        {"name": "Days Since Successful Scan", "sensor": {"name": "Patch - Scan Age"}, "values": ["2 Days"]},
        {"name": "Reason", "sensor": {"name": "Reboot Required"}, "values": ["SYSTEM\\CurrentControlSet\\Control"]},
        {"name": "Pending", "sensor": {"name": "Reboot Required"}, "values": ["Yes"]},
        {"name": "Drive", "sensor": {"name": "BitLocker Details"}, "values": ["C:"]},
        {"name": "Protection Status", "sensor": {"name": "BitLocker Details"}, "values": ["Protection On"]}]


def _cve(cve, product="Python", excepted=False):
    return {"cveId": cve, "cvssScoreV3": 7.5, "isCisaKev": False, "epssScore": 0.02, "firstFound": "2026-10-01",
            "lastFound": "2026-11-25", "excepted": excepted, "detectedProducts": [product], "detectedCPEs": ["cpe:/a:python:python:3.12.x"],
            "remediation": "Upgrade", "tests": [{"testResult": "true", "actualValues": "filepath=C:\\Python312\\python.exe,product_version=3.12.6",
                                                 "expectedStates": "less than 3.12.11"}]}


class FakeGateway:
    def __init__(self, endpoints):
        self.endpoints, self.queries = endpoints, []

    async def query(self, q):
        self.queries.append(q)
        return {"now": "x"}

    async def pages(self, field, fields, size, args=""):
        self.queries.append(fields)
        yield [dict(e) for e in self.endpoints]


def test_client_is_read_only_and_allow_listed():
    from api.integrations.tanium_gql import Gateway, TaniumError, base_url, sensor_args
    assert base_url("https://acme-api.cloud.tanium.com/x/y") == "https://acme-api.cloud.tanium.com"
    for bad in ("http://acme-api.cloud.tanium.com", "https://u:p@acme-api.cloud.tanium.com", "", "acme-api.cloud.tanium.com"):
        with pytest.raises(TaniumError):
            base_url(bad)
    with pytest.raises(TaniumError):
        sensor_args(["BitLocker Key"])           # recovery keys are never read
    assert 'params: [{name: "iAge"' in sensor_args(["Patch Installation History"])
    gw = Gateway("https://acme-api.cloud.tanium.com", "token-" + "a" * 58)
    import asyncio
    with pytest.raises(TaniumError):
        asyncio.run(gw.query("mutation { actionCreate { id } }"))


@pytest.mark.asyncio
async def test_client_sends_get_with_the_token_header(monkeypatch):
    import api.integrations.tanium_gql as g
    seen = {}

    class Resp:
        status_code = 200

        def json(self):
            return {"data": {"now": "2026-11-27"}}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None, headers=None):
            seen.update(url=url, params=params, headers=headers)
            return Resp()

        async def post(self, *a, **k):
            raise AssertionError("never POST")
    monkeypatch.setattr(g, "safe_client", lambda **k: Client())
    assert await g.Gateway("https://acme-api.cloud.tanium.com", "token-x").query("{ now }") == {"now": "2026-11-27"}
    assert seen["url"].endswith("/plugin/products/gateway/graphql") and seen["headers"]["session"] == "token-x"
    assert seen["params"] == {"query": "{ now }"}


def test_patch_and_encryption_parsing():
    from api.integrations.tanium import view
    v = view({"id": "1", "name": "pc", "isEncrypted": True, "sensorReadings": {"columns": SENS}, "primaryUser": {"name": "Elmer Fudd"}}, True)
    p = v["patch"]
    assert p["last_installed"] == "2026-11-19" and p["last_source"] == "Windows Update" and len(p["recent"]) == 2
    assert p["scan_age_days"] == 2 and p["reboot_required"] is True
    assert v["encrypted"] is True and v["bitlocker"][0]["protection"] == "Protection On"
    assert "encrypted" not in view({"id": "1", "name": "pc", "isEncrypted": True}, False)   # Pull disk encryption off
    from api.integrations.tanium_vulns import proof
    got = proof({"tests": [{"testResult": "true", "actualValues": "filepath=C:\\Users\\efudd\\AppData\\python.exe"}]})
    assert "efudd" not in got["tests"][0]["found"]   # the person's profile folder never leaves Tanium


@pytest.mark.asyncio
async def test_sync_endpoints_software_vulns_and_closing(db, monkeypatch):
    from api.integrations import tanium as t
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.software import SoftwareInstall
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    tag = uuid.uuid4().hex[:6]
    cfg = IntegrationConfig(vendor=Vendor.tanium, name=f"T {tag}", config={})
    known = Device(hostname=f"tan{tag}a", device_type=DeviceType.workstation, source="ldap", sources=",ldap,")
    db.add_all([cfg, known])
    await db.commit()
    eps = [{"id": "11", "name": f"tan{tag}a", "isEncrypted": False, "eidLastSeen": "2026-11-26T10:00:00Z", "sensorReadings": {"columns": SENS},
            "installedApplications": [{"name": "Python 3.12", "version": "3.12.6"}],
            "compliance": {"cveFindings": [_cve("CVE-2025-4516"), _cve("CVE-2025-1111"), _cve("CVE-2025-2222", excepted=True)]}},
           {"id": "12", "name": f"tan{tag}b", "isEncrypted": True,
            "compliance": {"cveFindings": [{"cveId": "[no results]"}]}}]
    gw = FakeGateway(eps)
    monkeypatch.setattr(t.TaniumConnector, "_gw", lambda self: gw)
    conn = t.TaniumConnector({"api_url": "https://acme-api.cloud.tanium.com", "api_token": "x"})
    conn.integration_id = str(cfg.id)
    await conn.sync(db)
    devs = {d.hostname: d for d in (await db.execute(select(Device).where(Device.hostname.like(f"tan{tag}%")))).scalars()}
    assert set(devs) == {f"tan{tag}a", f"tan{tag}b"} and ",tanium," in devs[f"tan{tag}a"].sources
    assert devs[f"tan{tag}a"].tanium["patch"]["last_installed"] == "2026-11-19"
    assert (await db.execute(select(SoftwareInstall).where(SoftwareInstall.device_id == known.id, SoftwareInstall.source == "tanium"))).scalars().first()
    rows = {v.cve_id: f for f, v in (await db.execute(select(Finding, Vulnerability).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                                                      .where(Finding.device_id == known.id))).all()}
    assert set(rows) == {"CVE-2025-4516", "CVE-2025-1111"}   # the excepted one isn't imported
    assert rows["CVE-2025-4516"].details["proof"]["tests"][0]["found"].endswith("3.12.6")
    # Next run: one CVE fixed, the other machine still has no results, and a third that was listed is gone
    eps[0]["compliance"] = {"cveFindings": [_cve("CVE-2025-4516")]}
    gw.endpoints = eps
    await conn.sync(db)
    st = {v.cve_id: f.status for f, v in (await db.execute(select(Finding, Vulnerability).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                                                           .where(Finding.device_id == known.id)
                                                           .execution_options(populate_existing=True))).all()}
    assert st == {"CVE-2025-4516": FindingStatus.open, "CVE-2025-1111": FindingStatus.remediated}
    gw.endpoints = [eps[1]]   # the first machine left Tanium (retired): its findings close
    await conn.sync(db)
    left = (await db.execute(select(Finding).where(Finding.device_id == known.id, Finding.status == FindingStatus.open)
                             .execution_options(populate_existing=True))).scalars().all()
    assert not left
    pf = await _posture(db)
    assert "tanium:devices:unencrypted" in pf
    await db.execute(delete(Finding).where(Finding.source == "tanium"))
    await db.execute(delete(SoftwareInstall).where(SoftwareInstall.source == "tanium"))
    await db.execute(delete(Device).where(Device.hostname.like(f"tan{tag}%")))
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cfg.id))
    await db.commit()


async def _posture(db):
    from api.models.identity import PostureFinding
    return {p.external_id for p in (await db.execute(select(PostureFinding).where(PostureFinding.source == "tanium",
                                                                                  PostureFinding.is_resolved.is_(False)))).scalars()}


@pytest.mark.asyncio
async def test_pull_options_skip_what_is_off(db, monkeypatch):
    from api.integrations import tanium as t
    from api.integrations.base import pulls
    assert pulls({}, "vulns") and pulls({"pull_vulns": True}, "vulns") and not pulls({"pull_vulns": False}, "vulns")
    gw = FakeGateway([])
    monkeypatch.setattr(t.TaniumConnector, "_gw", lambda self: gw)
    conn = t.TaniumConnector({"api_url": "https://a.example", "api_token": "x", "pull_vulns": False, "pull_software": False})
    await conn.sync(db)
    assert not any("cveFindings" in q or "installedApplications" in q for q in gw.queries)


@pytest.mark.asyncio
async def test_device_tab_hides_people_from_other_roles(db, client_admin, client_read_only):
    from api.models.device import Device, DeviceType
    d = Device(hostname=f"tab{uuid.uuid4().hex[:6]}", device_type=DeviceType.workstation, source="tanium", sources=",tanium,",
               tanium={"patch": {"last_installed": "2020-01-02", "last_source": "Tanium"}, "primary_user": "Elmer Fudd", "encrypted": True})
    db.add(d)
    await db.commit()
    a = (await client_admin.get(f"/api/v1/devices/{d.id}/tanium")).json()
    assert a["available"] and a["users"]["primary"] == "Elmer Fudd" and a["patch"]["view"]["stale"] is True
    assert (await client_admin.get(f"/api/v1/devices/{d.id}")).json()["last_patch"]["date"] == "2020-01-02"
    r = await client_read_only.get(f"/api/v1/devices/{d.id}/tanium")
    assert r.status_code in (200, 403, 404) and (r.status_code != 200 or r.json().get("users") is None)
    await db.execute(delete(Device).where(Device.id == d.id))
    await db.commit()


@pytest.mark.asyncio
async def test_a_deadlocked_page_is_retried(db, monkeypatch):
    from sqlalchemy.exc import DBAPIError
    from api.integrations import tanium as t
    import asyncio
    real = asyncio.sleep
    monkeypatch.setattr(t.asyncio, "sleep", lambda s: real(0))
    calls = []

    async def page():
        calls.append(1)
        if len(calls) < 3:
            raise DBAPIError("UPDATE devices", {}, Exception("deadlock detected"))
        return 7
    assert await t.retry(db, page) == 7 and len(calls) == 3

    async def other():
        raise DBAPIError("UPDATE devices", {}, Exception("some other error"))
    with pytest.raises(DBAPIError):
        await t.retry(db, other)   # anything but a deadlock fails at once
