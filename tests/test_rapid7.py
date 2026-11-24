"""Rapid7 connector plumbing: regions, modes, severity floors, registration."""
from __future__ import annotations

import uuid

import pytest

from api.integrations import rapid7_common as r7
from api.integrations.base import get_connector


def test_region_defaults_to_us():
    assert r7.platform_base({}) == "https://us.api.insight.rapid7.com"


@pytest.mark.parametrize("raw,expected", [("EU", "eu"), ("us-east-1", "us"), (" ca ", "ca"), ("ap-southeast-2", "au")])
def test_region_aliases(raw, expected):
    assert r7.region({"region": raw}) == expected


@pytest.mark.parametrize("bad", ["evil.example.com", "us.attacker", "../", "us@203.0.113.5"])
def test_region_rejects_anything_off_list(bad):
    with pytest.raises(ValueError):
        r7.platform_base({"region": bad})


@pytest.mark.parametrize("value,ok", [("google-chrome-cve-2026-0001", True), ("a'b", False), ("x]", False), ("", False)])
def test_safe_id(value, ok):
    assert r7.safe_id(value) is ok


def test_int_cfg_clamps_and_survives_junk():
    assert r7.int_cfg({"n": "99999"}, "n", 10, 1, 500) == 500
    assert r7.int_cfg({"n": "nope"}, "n", 10, 1, 500) == 10


@pytest.mark.parametrize("vendor", ["rapid7_appsec", "rapid7_insightvm", "rapid7_cloudsec"])
def test_rapid7_connectors_are_registered(vendor):
    import api.integrations  # noqa: F401
    assert get_connector(vendor, {"api_key": "example-not-a-key"}) is not None


def test_insightvm_mode_detection():
    cloud = get_connector("rapid7_insightvm", {"api_key": "example-not-a-key"})
    console = get_connector("rapid7_insightvm", {"host": "insightvm.acme.example.com", "username": "u", "password": "p"})
    forced = get_connector("rapid7_insightvm", {"mode": "console", "api_key": "example-not-a-key", "host": "h"})
    assert cloud._cloud and not console._cloud and not forced._cloud
    assert cloud._v4 == "https://us.api.insight.rapid7.com/vm/v4/integration"


def test_insightvm_severity_floor():
    c = get_connector("rapid7_insightvm", {"api_key": "x", "min_severity": "critical"})
    assert c._severity_filter() == "vulnerability.severity IN ['Critical']"
    junk = get_connector("rapid7_insightvm", {"api_key": "x", "min_severity": "' OR 1=1"})
    assert junk._severities() == ("Critical", "Severe")


def test_appsec_severity_floor_and_base():
    c = get_connector("rapid7_appsec", {"api_key": "x", "region": "eu", "min_severity": "medium"})
    assert c._min_severities() == ["CRITICAL", "HIGH", "MEDIUM"]
    assert c._base == "https://eu.api.insight.rapid7.com/ias/v1"


def test_cloudsec_requires_https_base():
    c = get_connector("rapid7_cloudsec", {"api_key": "x", "base_url": "http://acme.insightcloudsec.com"})
    with pytest.raises(ValueError):
        _ = c._base
    ok = get_connector("rapid7_cloudsec", {"api_key": "x", "base_url": "https://acme.insightcloudsec.com/"})
    assert ok._base == "https://acme.insightcloudsec.com/v2"
    assert ok._headers()["Api-Key"] == "x"


@pytest.mark.asyncio
async def test_cloudsec_login_redirect_is_not_success(monkeypatch):
    import httpx

    from api.integrations import rapid7_cloudsec

    def fake_client(**_):
        def handler(request):
            assert request.headers["Api-Key"] == "example-not-a-key"
            if request.url.host == "good.example.com":
                return httpx.Response(200, json={"clouds": []})
            return httpx.Response(302, headers={"location": "https://login.example.com/"})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(rapid7_cloudsec, "safe_client", fake_client)
    bad = get_connector("rapid7_cloudsec", {"api_key": "example-not-a-key", "base_url": "https://bad.example.com"})
    good = get_connector("rapid7_cloudsec", {"api_key": "example-not-a-key", "base_url": "https://good.example.com"})
    assert await bad.test_connection() is False
    assert await good.test_connection() is True


def test_parse_dt_assumes_utc_for_naive():
    assert r7.parse_dt("2022-04-20 16:48:02").tzinfo is not None


@pytest.mark.asyncio
async def test_insightvm_streams_every_page_and_trims_severity(db, monkeypatch):
    import json

    import httpx
    from sqlalchemy import func, select

    from api.integrations import rapid7_insightvm
    from api.models.device import Device
    from api.models.vuln import Finding, Vulnerability

    run = uuid.uuid4().hex[:6]

    def asset(i):
        return {"id": f"{run}-a{i}", "host_name": f"ivm-{run}-{i}.acme.example", "ip": f"198.51.100.{i}",
                "last_assessed_for_vulnerabilities": "2026-11-01T10:00:00Z",
                "same": [{"vulnerability_id": f"{run}-crit", "first_found": "2026-01-01T00:00:00Z"},
                         {"vulnerability_id": f"{run}-low"}]}

    pages = {None: ([asset(i) for i in range(3)], "c1"), "c1": ([asset(i) for i in range(3, 5)], None)}
    vuln_calls = []

    def fake_client(**_):
        def handler(request):
            if request.url.path.endswith("/assets"):
                data, nxt = pages[request.url.params.get("cursor")]
                return httpx.Response(200, json={"data": data, "metadata": {"cursor": nxt}})
            q = json.loads(request.content)["vulnerability"]
            vuln_calls.append(q)
            out = []
            if f"'{run}-crit'" in q:
                out.append({"id": f"{run}-crit", "title": "Acme crit", "severity": "Critical", "cves": "CVE-2026-1111",
                            "cvss_v3_score": 9.8})
            if f"'{run}-low'" in q:
                out.append({"id": f"{run}-low", "title": "Acme low", "severity": "Moderate"})
            return httpx.Response(200, json={"data": out})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(rapid7_insightvm, "safe_client", fake_client)
    c = get_connector("rapid7_insightvm", {"api_key": "example-not-a-key", "min_severity": "severe"})
    count = await c.sync(db)
    assert count == 5  # one kept finding per asset; the Moderate one is trimmed
    assert len(vuln_calls) == 1  # catalog fetched once, reused for page two
    devs = (await db.execute(select(Device).where(Device.source_id.like(f"{run}-%")))).scalars().all()
    assert len(devs) == 5 and all(d.last_seen is not None for d in devs)
    n = (await db.execute(select(func.count()).select_from(Finding).join(Vulnerability)
                          .where(Vulnerability.source_vuln_id == f"{run}-crit"))).scalar_one()
    assert n == 5
    assert c.config.get("max_assets") is None  # no cap unless someone sets one


@pytest.mark.asyncio
async def test_a_host_back_from_cleanup_is_read_in_full(db, monkeypatch):
    import json
    from datetime import datetime, timedelta, timezone

    import httpx
    from sqlalchemy import select

    from api.integrations import rapid7_insightvm
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    run = uuid.uuid4().hex[:6]
    aid = f"{run}-back"
    dev = Device(hostname=f"back-{run}", device_type=DeviceType.server, source="rapid7_insightvm", source_id=aid,
                 pruned_at=datetime.now(timezone.utc) - timedelta(days=1))
    v = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"{run}-old", title="Old finding", cvss_base=9.0)
    db.add_all([dev, v])
    await db.commit()
    bodies = []

    def fake_client(**_):
        def handler(request):
            if request.url.path.endswith("/assets"):
                body = json.loads(request.content)
                bodies.append((dict(request.url.params), body))
                full = "asset.id IN" in (body.get("asset") or "")
                findings = {"same": [{"vulnerability_id": f"{run}-old"}]} if full else {"new": []}
                return httpx.Response(200, json={"data": [{"id": aid, "host_name": f"back-{run}", **findings}], "metadata": {}})
            return httpx.Response(200, json={"data": []})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(rapid7_insightvm, "safe_client", fake_client)
    c = get_connector("rapid7_insightvm", {"api_key": "example-not-a-key"})
    c.integration_id = None
    monkeypatch.setattr(c, "_incremental_since", lambda state, now: now - timedelta(hours=6))
    await c.sync(db)
    params, body = bodies[-1]
    assert body["asset"] == f"asset.id IN ['{aid}']" and params["includeSame"] == "true"   # just that host, everything it has
    f = (await db.execute(select(Finding).where(Finding.device_id == dev.id))).scalars().all()
    assert len(f) == 1
    again = (await db.execute(select(Device).where(Device.id == dev.id).execution_options(populate_existing=True))).scalar_one()
    assert again.pruned_at is None
