"""KEV/EPSS enrichment and the scoring roll-ups the lists depend on."""
from __future__ import annotations

import uuid
from datetime import date

import httpx
import pytest


def test_parse_kev_and_epss_reject_junk():
    from api.enrichment.kev_epss import parse_epss, parse_kev

    kev = parse_kev({"vulnerabilities": [
        {"cveID": "CVE-2026-0001", "dateAdded": "2026-01-02"},
        {"cveID": "cve-2026-0002", "dateAdded": "bad-date"},
        {"cveID": "'; drop table", "dateAdded": "2026-01-02"},
    ]})
    assert kev == {"CVE-2026-0001": date(2026, 1, 2), "CVE-2026-0002": None}
    epss = parse_epss({"data": [
        {"cve": "CVE-2026-0001", "epss": "0.97"},
        {"cve": "CVE-2026-0002", "epss": "7"},      # out of range
        {"cve": "CVE-2026-0003", "epss": "nope"},
    ]})
    assert epss == {"CVE-2026-0001": 0.97}


@pytest.mark.asyncio
async def test_enrich_sets_kev_and_epss(db, monkeypatch):
    from sqlalchemy import select

    from api.enrichment import kev_epss
    from api.models.vuln import Vulnerability

    tag = uuid.uuid4().int % 10**5
    cves = [f"CVE-2099-{tag:05d}{i}" for i in range(3)]  # digits only, like real CVE ids
    for c in cves:
        db.add(Vulnerability(cve_id=c, title=c, source="t_enrich"))
    await db.commit()

    calls = []

    def fake_client(**_):
        def handler(request):
            calls.append(request.url.host)
            if request.url.host == "www.cisa.gov":
                return httpx.Response(200, json={"vulnerabilities": [{"cveID": cves[0], "dateAdded": "2026-03-04"}]})
            asked = request.url.params["cve"].split(",")
            return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.5"} for c in asked if c in cves]})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(kev_epss, "safe_client", fake_client)
    monkeypatch.setattr(kev_epss.asyncio, "sleep", lambda *_: _noop())
    result = await kev_epss.enrich(db)
    assert result["kev"] >= 1 and result["epss"] >= 3
    rows = {v.cve_id: v for v in (await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id.in_(cves)).execution_options(populate_existing=True))).scalars()}
    assert rows[cves[0]].is_kev and rows[cves[0]].kev_added_date == date(2026, 3, 4)
    assert not rows[cves[1]].is_kev
    assert all(rows[c].epss_score == 0.5 for c in cves)
    assert set(calls) == {"www.cisa.gov", "api.first.org"}  # only the two fixed feeds


async def _noop():
    return None


@pytest.mark.asyncio
async def test_epss_keeps_what_it_got_when_first_stops_answering(db, monkeypatch):
    """A refused request part way (FIRST rate-limits) keeps the scores already fetched, so the next run asks only the
    rest instead of starting over (which cost every post-sync run its full refresh)."""
    from api.enrichment import kev_epss
    from api.models.vuln import Vulnerability
    tag = uuid.uuid4().int % 10**5
    db.add_all([Vulnerability(cve_id=f"CVE-2098-{tag:05d}{i}", title="x", source="t_epss") for i in range(6)])
    await db.commit()
    asks = []

    def fake_client(**_):
        def handler(request):
            if request.url.host == "www.cisa.gov":
                return httpx.Response(200, json={"vulnerabilities": []})
            asked = request.url.params["cve"].split(",")
            asks.append(len(asked))
            if len(asks) == 2:
                return httpx.Response(429, json={})
            return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.1"} for c in asked]})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(kev_epss, "safe_client", fake_client)
    monkeypatch.setattr(kev_epss.asyncio, "sleep", lambda *_: _noop())
    monkeypatch.setattr(kev_epss, "_EPSS_BATCH", 2)
    first = await kev_epss.enrich(db)
    assert first["epss"] >= 2 and len(asks) == 2           # the first batch was kept, then it stopped
    asks.clear()
    second = await kev_epss.enrich(db)
    assert second["epss_asked"] == first["epss_asked"] - 2  # only what wasn't answered is asked again


@pytest.mark.asyncio
async def test_small_kev_download_does_not_clear_flags(db):
    from sqlalchemy import select

    from api.enrichment.kev_epss import apply_kev
    from api.models.vuln import Vulnerability

    c = f"CVE-2098-{uuid.uuid4().int % 10**6:06d}"
    db.add(Vulnerability(cve_id=c, title=c, source="t_enrich", is_kev=True))
    await db.commit()
    await apply_kev(db, {"CVE-2026-0001": None}, [c])  # truncated feed: 1 entry
    v = (await db.execute(select(Vulnerability).where(Vulnerability.cve_id == c)
                          .execution_options(populate_existing=True))).scalar_one()
    assert v.is_kev


@pytest.mark.asyncio
async def test_scoring_fills_finding_scores_and_device_counts(db):
    from sqlalchemy import func, select

    from api.models.device import Device, DeviceType
    from api.models.risk import RiskScoreHistory
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    from api.scoring.engine import recalculate_device

    dev = Device(hostname="score.acme.example", device_type=DeviceType.server, source="t_score")
    db.add(dev)
    await db.flush()
    for i, kev in enumerate([True, False, False]):
        v = Vulnerability(cve_id=f"CVE-2097-{uuid.uuid4().int % 10**5:05d}{i}", title="x", cvss_base=9.0, is_kev=kev, source="t_score")
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=dev.id, vuln_id=v.id, source="t_score", status=FindingStatus.open))
    await db.commit()

    await recalculate_device(dev, db)
    await recalculate_device(dev, db)  # unchanged: no second history row
    assert dev.open_findings == 3 and dev.kev_findings == 1 and dev.risk_grade is not None
    scores = (await db.execute(select(Finding.composite_score).where(Finding.device_id == dev.id))).scalars().all()
    assert all(s is not None for s in scores)
    hist = (await db.execute(select(func.count()).select_from(RiskScoreHistory)
                             .where(RiskScoreHistory.entity_id == dev.id))).scalar_one()
    assert hist == 1


@pytest.mark.asyncio
async def test_sync_by_id_reports_success(db, monkeypatch):
    from api.integrations import base
    from api.models.integration import IntegrationConfig, Vendor

    cfg = IntegrationConfig(vendor=Vendor.rapid7_appsec, name="ACME test", is_enabled=True, config={"api_key": "x"})
    db.add(cfg)
    await db.commit()

    class Ok:
        async def sync(self, _db):
            return 3

    class Boom:
        async def sync(self, _db):
            raise RuntimeError("nope")

    monkeypatch.setattr(base, "get_connector", lambda *_: Ok())
    assert await base.sync_by_id(db, str(cfg.id)) is True
    monkeypatch.setattr(base, "get_connector", lambda *_: Boom())
    assert await base.sync_by_id(db, str(cfg.id)) is False
