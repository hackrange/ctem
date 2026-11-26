"""FairTPRM v2 connector against a fake FairTPRM."""
from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from api.integrations import fairtprm


def _fake(handler):
    def factory(**_kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return factory


VENDORS = [
    {"id": 7, "vendor_name": "ACME Payroll", "vendor_domain": "payroll.acme.example", "status": "approved", "vendor_tier": "1"},
    {"id": 8, "vendor_name": "ACME Catering", "vendor_domain": "food.acme.example", "status": "draft", "vendor_tier": None},
]


def _handler(seen):
    def handle(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.path, req.headers.get("authorization")))
        if req.headers.get("authorization") != "Bearer tok-example-only":
            return httpx.Response(401, json={"error": "Invalid token, expired, or IP not whitelisted"})
        if req.url.path == "/api/v2/vendors":
            return httpx.Response(200, json={"data": VENDORS, "total": 2})
        if req.url.path == "/api/v2/vendors/7/srs":
            return httpx.Response(200, json={"data": [{"score": 285, "score_grade": "D", "critical_risks": 2,
                                                       "high_risks": 3, "scored_at": "2026-11-01 10:00:00"}]})
        if req.url.path == "/api/v2/vendors/8/srs":
            return httpx.Response(200, json={"data": []})
        if req.url.path == "/api/v2/fair/analyses":
            return httpx.Response(200, json={"data": [{"vendor_name": "acme  catering", "risk_level": "High",
                                                       "annualized_loss_expectancy": 120000}]})
        return httpx.Response(404, json={"error": "Resource not found"})
    return handle


@pytest.mark.parametrize("base", ["https://tprm.acme.example", "https://tprm.acme.example/", "https://tprm.acme.example/api",
                                  "https://tprm.acme.example/api/v2", "https://tprm.acme.example/api/v2/", "https://tprm.acme.example/api/v1"])
def test_base_url_forms_all_land_on_v2(base):
    assert fairtprm.FairTPRMConnector({"base_url": base, "api_key": "x"})._api == "https://tprm.acme.example/api/v2"


@pytest.mark.asyncio
async def test_sync_maps_vendors_ratings_and_fair(db, monkeypatch):
    from api.models.risk import ThirdPartyRisk
    seen = []
    monkeypatch.setattr(fairtprm, "safe_client", _fake(_handler(seen)))
    conn = fairtprm.FairTPRMConnector({"base_url": "https://tprm.acme.example/api/v2", "api_key": "tok-example-only",
                                       "pull_grc": "false"})
    assert await conn.sync(db) == 2
    assert all(auth == "Bearer tok-example-only" for _, auth in seen)
    rows = {r.external_id: r for r in (await db.execute(select(ThirdPartyRisk).where(ThirdPartyRisk.source == "fairtprm"))).scalars()}
    payroll, catering = rows["7"], rows["8"]
    assert payroll.supplier_name == "ACME Payroll" and payroll.tier == "tier1"
    assert payroll.risk_score == 70.0 and payroll.risk_grade == "D" and payroll.open_gaps == 5
    assert payroll.last_assessment is not None
    assert catering.risk_score == 75.0 and catering.risk_grade == "D"  # no rating, so FAIR "High" fills in
    assert catering.extra["fair"]["annualized_loss_expectancy"] == 120000


@pytest.mark.asyncio
async def test_rejected_token_fails_the_sync_with_a_useful_reason(db, monkeypatch):
    monkeypatch.setattr(fairtprm, "safe_client", _fake(_handler([])))
    conn = fairtprm.FairTPRMConnector({"base_url": "https://tprm.acme.example", "api_key": "wrong"})
    with pytest.raises(fairtprm.FairTPRMError, match="IP whitelist"):
        await conn.sync(db)
    assert await conn.test_connection() is False


@pytest.mark.asyncio
async def test_unrated_vendor_is_not_graded_a_and_duplicates_dont_break_sync(db, monkeypatch):
    from api.models.risk import ThirdPartyRisk

    def handle(req):
        if req.url.path == "/api/v2/vendors":
            return httpx.Response(200, json={"data": [{"id": 99, "vendor_name": "ACME Unrated"}], "total": 1})
        return httpx.Response(200, json={"data": []})
    monkeypatch.setattr(fairtprm, "safe_client", _fake(handle))
    # Leftovers from two syncs that raced before the lock existed
    db.add_all([ThirdPartyRisk(source="fairtprm", external_id="99", supplier_name="x") for _ in range(2)])
    await db.commit()
    await fairtprm.FairTPRMConnector({"base_url": "https://tprm.acme.example", "api_key": "k"}).sync(db)
    rows = (await db.execute(select(ThirdPartyRisk).where(ThirdPartyRisk.external_id == "99"))).scalars().all()
    assert any(r.risk_grade == fairtprm.UNRATED and r.supplier_name == "ACME Unrated" for r in rows)


@pytest.mark.asyncio
async def test_second_concurrent_sync_bows_out(db, monkeypatch):
    from api.integrations import base

    async def held(_iid, _runner="app"):
        return False
    monkeypatch.setattr(base, "_sync_lock", held)
    called = []
    monkeypatch.setattr(base, "_sync_by_id", lambda *a: called.append(a))
    assert await base.sync_by_id(db, "00000000-0000-0000-0000-000000000000") is False
    assert not called
