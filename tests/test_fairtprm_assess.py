"""FairTPRM assessment results and audits: mirrored, encrypted where it matters, shown on the GRC page."""
from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select, text

from api.integrations import fairtprm

LIST = [{"id": 7, "assessment_ref": "FA-007", "title": "2026 CSF maturity", "assessment_type": "periodic",
         "status": "completed", "actual_end": "2026-10-31", "overall_fairscore": "2.75", "overall_compliance_pct": "71.50",
         "updated_at": "2026-11-01 09:00:00", "progress": {"total_questions": 120, "answered": 118, "pending": 2,
                                                          "validated": 100, "progress_pct": 98.3, "validation_pct": 84.7},
         "report_encrypted_data": "should never be read"},
        {"id": 8, "assessment_ref": "FA-008", "title": "Q1 targeted", "status": "in_progress", "planned_start": "2027-01-05"}]
DETAIL = {**LIST[0],
          "domain_scores": [{"domain_code": "PR.AA", "domain_name": "Identity", "average_score": "3.10", "target_score": "3.50",
                             "questions_total": 10, "questions_answered": 10, "conforming_count": 7, "partial_count": 2,
                             "non_conforming_count": 1, "not_applicable_count": 0}],
          "framework_compliance": [{"framework_code": "ISO27001", "framework_name": "ISO/IEC 27001", "total_mapped": 40,
                                    "conforming": 30, "partial": 6, "non_conforming": 4, "not_applicable": 0,
                                    "compliance_pct": 82.5, "avg_maturity": 2.9}],
          "gaps": [{"question_ref": "Q-PR-04", "question_text": "Is MFA enforced for admins?", "domain_code": "PR.AA",
                    "domain_name": "Identity", "conformity_status": "non_conforming", "maturity_rating": 1,
                    "validation_status": "validated", "notes": "secret assessor note"},
                   {"question_ref": "Q-X", "conformity_status": "made_up"}]}
AUDITS = [{"id": 3, "audit_ref": "AUD-3", "title": "SOC 2 Type II", "audit_type": "external", "status": "remediation",
           "framework_code": "SOC2", "planned_start": "2026-09-01", "findings_count": 2, "critical_findings": 1}]
AUDIT_DETAIL = {**AUDITS[0], "notes": "internal", "findings": [
    {"finding_ref": "F-1", "title": "No access reviews", "severity": "critical", "finding_type": "nonconformity",
     "status": "open", "due_date": "2026-12-31", "remediation_plan": "private plan"},
    {"finding_ref": "F-2", "title": "Old policy", "severity": "low", "status": "remediated"}]}


def _factory(with_assessments=True):
    def handle(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.startswith("/api/v2/grc/assessments") and not with_assessments:
            return httpx.Response(404, json={"error": "GRC resource not found: assessments"})
        routes = {"/api/v2/grc/assessments": LIST, "/api/v2/grc/assessments/7": DETAIL,
                  "/api/v2/grc/assessments/8": {**LIST[1], "domain_scores": [], "framework_compliance": [], "gaps": []},
                  "/api/v2/grc/audits": AUDITS, "/api/v2/grc/audits/3": AUDIT_DETAIL}
        if p == "/api/v2/vendors":
            return httpx.Response(200, json={"data": [], "total": 0})
        return httpx.Response(200, json={"data": routes.get(p, [])})
    return lambda **_kw: httpx.AsyncClient(transport=httpx.MockTransport(handle))


def _conn():
    return fairtprm.FairTPRMConnector({"base_url": "https://tprm.acme.example", "api_key": "k"})


@pytest.mark.asyncio
async def test_assessments_and_audits_mirror_and_show(db, monkeypatch, client_cyber):
    from api.models.grc import GrcAssessment, GrcAudit
    monkeypatch.setattr(fairtprm, "safe_client", _factory())
    await _conn().sync(db)

    a = (await db.execute(select(GrcAssessment).where(GrcAssessment.external_id == "7"))).scalar_one()
    assert (a.fairscore, a.compliance_pct, a.progress["answered"]) == (2.75, 71.5, 118)
    assert a.domain_scores[0]["target"] == 3.5 and a.framework_compliance[0]["compliance_pct"] == 82.5
    assert [g["ref"] for g in a.gaps] == ["Q-PR-04"] and "notes" not in a.gaps[0]  # bad status dropped, notes never kept
    raw = (await db.execute(text("SELECT gaps FROM grc_assessments WHERE external_id = '7'"))).scalar_one()
    assert "MFA" not in str(raw)  # gaps are encrypted at rest
    audit = (await db.execute(select(GrcAudit).where(GrcAudit.external_id == "3"))).scalar_one()
    assert [f["severity"] for f in audit.findings] == ["critical", "low"] and "remediation_plan" not in audit.findings[0]

    d = (await client_cyber.get("/api/v1/grc/assessments")).json()
    assert d["available"] and d["latest"]["ref"] == "FA-007" and d["latest"]["non_conforming"] == 1
    assert d["latest"]["domain_scores"][0]["code"] == "PR.AA"
    assert {x["ref"] for x in d["assessments"]} >= {"FA-007", "FA-008"}
    one = (await client_cyber.get(f"/api/v1/grc/assessments/{a.id}")).json()
    assert one["gaps"][0]["question"] == "Is MFA enforced for admins?"
    assert (await client_cyber.get("/api/v1/grc/assessments/00000000-0000-0000-0000-000000000000")).status_code == 404
    au = (await client_cyber.get("/api/v1/grc/audits")).json()["audits"]
    assert any(x["ref"] == "AUD-3" and x["open_findings"] == 1 and x["critical_findings"] == 1 for x in au)
    page = await client_cyber.get(f"/grc/assessments/{a.id}")
    assert page.status_code == 200


@pytest.mark.asyncio
async def test_older_fairtprm_without_assessments_is_not_a_failure(db, monkeypatch, client_cyber):
    from api.models.grc import GrcAudit
    monkeypatch.setattr(fairtprm, "safe_client", _factory(with_assessments=False))
    await _conn().sync(db)  # would raise FairTPRMError if the 404 counted as a problem
    assert (await client_cyber.get("/api/v1/grc/assessments")).json()["available"] is False
    assert (await db.execute(select(GrcAudit).where(GrcAudit.external_id == "3"))).scalar_one().title == "SOC 2 Type II"
    monkeypatch.setattr(fairtprm, "safe_client", _factory())
    await _conn().sync(db)
    assert (await client_cyber.get("/api/v1/grc/assessments")).json()["available"] is True
