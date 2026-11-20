"""FairTPRM GRC mirror: frameworks, controls, risks, evidence, monitors; drift and compliance views."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from api.integrations import fairtprm

PAST = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
SOON = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")

GRC = {
    "/api/v2/grc/dashboard": {"frameworks": [{"framework_id": 1, "framework_code": "ISO27001", "total_requirements": 93,
                                              "fully_implemented": 60, "partially_implemented": 10, "in_progress": 5,
                                              "planned": 3, "not_applicable": 2, "compliance_percentage": "64.52"}],
                              "controls_total": 2, "evidence_expired": 1, "monitors_failing": 0},
    "/api/v2/grc/frameworks": [{"id": 1, "code": "ISO27001", "name": "ISO/IEC 27001", "is_active": 1, "compliance_year": 2026}],
    "/api/v2/grc/controls": [
        {"id": 11, "control_ref": "CTL-EDR", "title": "Endpoint protection", "effectiveness": "ineffective",
         "implementation_status": "implemented", "frameworks": "ISO27001, SOC2", "evidence_count": 2, "is_active": 1},
        {"id": 12, "control_ref": "CTL-MFA", "title": "MFA", "effectiveness": "effective", "frameworks": "SOC2", "is_active": 1}],
    "/api/v2/grc/risks": [
        {"id": 21, "risk_ref": "RISK-001", "title": "Ransomware on endpoints", "risk_treatment": "mitigate",
         "status": "treating", "control_ids": "[11]", "inherent_risk_score": "16.00", "residual_risk_score": "6.00",
         "review_date": "2099-01-01", "vendor_id": None},
        {"id": 22, "risk_ref": "RISK-002", "title": "Phishing", "risk_treatment": "mitigate", "status": "monitoring",
         "control_ids": [12], "residual_risk_score": "4.00", "review_date": "2099-01-01"},
        {"id": 23, "risk_ref": "RISK-003", "title": "Unlinked", "risk_treatment": "mitigate", "status": "identified",
         "control_ids": None, "review_date": "2001-01-01"}],
    "/api/v2/grc/evidence": [
        {"id": 31, "evidence_ref": "EV-1", "title": "Old pentest", "evidence_type": "report", "status": "expired",
         "valid_until": PAST, "is_expired": 1},
        {"id": 32, "evidence_ref": "EV-2", "title": "Policy", "evidence_type": "policy", "status": "current", "valid_until": SOON}],
    "/api/v2/grc/monitors": [{"id": 41, "name": "EDR via CTEM", "check_type": "ctem_edr_coverage", "control_ids": "[11]",
                              "is_enabled": 1, "last_result": "fail"}],
}


def _client_factory(routes, fail=()):
    def handle(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path in fail:
            return httpx.Response(500, json={"error": "Internal server error"})
        if path == "/api/v2/vendors":
            return httpx.Response(200, json={"data": [], "total": 0})
        if path in routes:
            return httpx.Response(200, json={"data": routes[path]})
        return httpx.Response(200, json={"data": []})
    return lambda **_kw: httpx.AsyncClient(transport=httpx.MockTransport(handle))


def _conn():
    return fairtprm.FairTPRMConnector({"base_url": "https://tprm.acme.example/api/v2", "api_key": "k"})


@pytest.mark.asyncio
async def test_grc_mirror_and_views(db, monkeypatch, client_cyber):
    from api.models.grc import GrcCheckResult, GrcControl, GrcFramework, GrcRisk
    monkeypatch.setattr(fairtprm, "safe_client", _client_factory(GRC))
    assert await _conn().sync(db) == 9
    fw = (await db.execute(select(GrcFramework).where(GrcFramework.external_id == "1"))).scalar_one()
    assert fw.compliance_percentage == 64.52 and fw.implemented == 60 and fw.total_requirements == 93
    ctl = (await db.execute(select(GrcControl).where(GrcControl.external_id == "11"))).scalar_one()
    assert ctl.frameworks == ["ISO27001", "SOC2"]
    risk = (await db.execute(select(GrcRisk).where(GrcRisk.external_id == "21"))).scalar_one()
    assert risk.control_ids == ["11"] and risk.residual_risk_score == 6.0

    db.add(GrcCheckResult(check_type="ctem_edr_coverage", check_version=1, result="fail",
                          summary="81% of active devices have healthy EDR", measured_at=datetime.now(timezone.utc)))
    await db.commit()
    risks = {r["risk_ref"]: r for r in (await client_cyber.get("/api/v1/grc/risks")).json()["risks"]}
    assert any("CTL-EDR is ineffective" in d for d in risks["RISK-001"]["drift"])
    assert any("ctem_edr_coverage is failing" in d for d in risks["RISK-001"]["drift"])
    assert risks["RISK-002"]["drift"] == []
    assert any("no controls are linked" in d for d in risks["RISK-003"]["drift"])
    assert any("review was due" in d for d in risks["RISK-003"]["drift"])
    only = (await client_cyber.get("/api/v1/grc/risks?drift_only=true")).json()
    assert {r["risk_ref"] for r in only["risks"]} == {"RISK-001", "RISK-003"}
    assert (await client_cyber.get("/api/v1/grc/risks?status=bogus")).status_code == 400

    controls = {c["control_ref"]: c for c in (await client_cyber.get("/api/v1/grc/controls")).json()["controls"]}
    assert controls["CTL-EDR"]["ctem_checks"][0]["result"] == "fail"
    ev = (await client_cyber.get("/api/v1/grc/evidence-status")).json()
    assert ev["expired"] >= 1 and ev["expiring_30d"] >= 1
    comp = (await client_cyber.get("/api/v1/grc/compliance")).json()
    assert {"slug": "ISO27001", "name": "ISO/IEC 27001", "score": 65, "passed": 60, "partial": 10, "total": 93} in comp["frameworks"]
    ov = (await client_cyber.get("/api/v1/grc/overview")).json()
    assert ov["fairtprm"]["evidence_expired"] == 1
    assert next(c for c in ov["checks"] if c["check_type"] == "ctem_edr_coverage")["used_by_fairtprm"] is True

    # Gone in FairTPRM means gone here
    smaller = {**GRC, "/api/v2/grc/risks": GRC["/api/v2/grc/risks"][:1]}
    monkeypatch.setattr(fairtprm, "safe_client", _client_factory(smaller))
    await _conn().sync(db)
    left = {r.external_id for r in (await db.execute(select(GrcRisk).where(GrcRisk.source == "fairtprm"))).scalars()}
    assert left == {"21"}


@pytest.mark.asyncio
async def test_failed_grc_resource_keeps_old_rows_and_fails_the_sync(db, monkeypatch):
    from api.models.grc import GrcRisk
    monkeypatch.setattr(fairtprm, "safe_client", _client_factory(GRC))
    await _conn().sync(db)
    before = {r.external_id for r in (await db.execute(select(GrcRisk).where(GrcRisk.source == "fairtprm"))).scalars()}
    monkeypatch.setattr(fairtprm, "safe_client", _client_factory(GRC, fail={"/api/v2/grc/risks"}))
    with pytest.raises(fairtprm.FairTPRMError, match="GRC data was incomplete"):
        await _conn().sync(db)
    after = {r.external_id for r in (await db.execute(select(GrcRisk).where(GrcRisk.source == "fairtprm"))).scalars()}
    assert after == before


@pytest.mark.asyncio
async def test_pull_grc_can_be_turned_off(db, monkeypatch):
    calls = []

    def handle(req):
        calls.append(req.url.path)
        return httpx.Response(200, json={"data": [], "total": 0})
    monkeypatch.setattr(fairtprm, "safe_client", lambda **_kw: httpx.AsyncClient(transport=httpx.MockTransport(handle)))
    await fairtprm.FairTPRMConnector({"base_url": "https://tprm.acme.example", "api_key": "k", "pull_grc": "false"}).sync(db)
    assert not any("/grc/" in c for c in calls)
