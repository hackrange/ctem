"""FairTPRM assessment results and audits: FairScore, compliance, domain scores, gaps and findings.

Needs FairTPRM's GET /api/v2/grc/assessments (newer FairTPRM). An older FairTPRM answers 404 there,
which isn't an error: the panel just says assessments aren't available yet.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.models.grc import GrcAssessment, GrcAudit

log = logging.getLogger("open-ctem.fairtprm")
MAX_DETAILS = 50          # newest assessments / audits whose detail we fetch each sync
_CONFORMITY = {"conforming", "partial", "non_conforming", "not_applicable", "not_assessed"}
_SEVERITY = {"informational", "low", "medium", "high", "critical"}


def _h():
    from api.integrations import fairtprm_grc as g
    return g


def _counts(d: dict, keys: tuple[str, ...]) -> dict:
    return {k: _h()._int(d.get(k)) for k in keys}


def _domain(d: dict) -> dict:
    g = _h()
    return {"code": g._text(d.get("domain_code"), 20), "name": g._text(d.get("domain_name"), 200),
            "score": g._num(d.get("average_score")), "target": g._num(d.get("target_score")),
            **_counts(d, ("questions_total", "questions_answered", "conforming_count", "partial_count",
                          "non_conforming_count", "not_applicable_count"))}


def _framework(f: dict) -> dict:
    g = _h()
    return {"code": g._text(f.get("framework_code"), 50), "name": g._text(f.get("framework_name"), 255),
            "compliance_pct": g._num(f.get("compliance_pct")), "avg_maturity": g._num(f.get("avg_maturity")),
            **_counts(f, ("total_mapped", "conforming", "partial", "non_conforming", "not_applicable"))}


def _gap(x: dict) -> dict | None:
    g = _h()
    status = str(x.get("conformity_status") or "")
    if status not in _CONFORMITY:
        return None
    rating = g._int(x.get("maturity_rating"))
    return {"ref": g._text(x.get("question_ref"), 50), "question": g._text(x.get("question_text"), 1000),
            "domain_code": g._text(x.get("domain_code"), 20), "domain": g._text(x.get("domain_name"), 200),
            "status": status, "maturity": rating if 1 <= rating <= 4 else None,
            "validation": g._text(x.get("validation_status"), 16)}


def _finding(x: dict) -> dict:
    g = _h()
    sev = str(x.get("severity") or "").lower()
    return {"ref": g._text(x.get("finding_ref"), 50), "title": g._text(x.get("title"), 500),
            "severity": sev if sev in _SEVERITY else None, "type": g._text(x.get("finding_type"), 32),
            "status": g._text(x.get("status"), 32), "due_date": g._text(x.get("due_date"), 10)}


def _fill_assessment(rec: GrcAssessment, a: dict) -> None:
    g = _h()
    rec.assessment_ref = g._text(a.get("assessment_ref"), 50)
    rec.title = str(a.get("title") or rec.assessment_ref or "Assessment")[:500]
    rec.assessment_type, rec.status = g._text(a.get("assessment_type"), 32), g._text(a.get("status"), 32)
    for f in ("planned_start", "planned_end", "actual_start", "actual_end"):
        setattr(rec, f, g._date(a.get(f)))
    rec.fairscore, rec.compliance_pct = g._num(a.get("overall_fairscore")), g._num(a.get("overall_compliance_pct"))
    rec.source_updated_at = g._dt(a.get("updated_at"))
    p = a.get("progress") if isinstance(a.get("progress"), dict) else {}
    rec.progress = {**_counts(p, ("total_questions", "answered", "pending", "validated")),
                    "progress_pct": g._num(p.get("progress_pct")), "validation_pct": g._num(p.get("validation_pct"))}
    if "domain_scores" in a:  # only the detail call carries these; keep the last good copy otherwise
        rec.domain_scores = [_domain(d) for d in a.get("domain_scores") or [] if isinstance(d, dict)][:100]
        rec.framework_compliance = [_framework(f) for f in a.get("framework_compliance") or [] if isinstance(f, dict)][:100]
        rec.gaps = [x for x in (_gap(y) for y in a.get("gaps") or [] if isinstance(y, dict)) if x][:500]


def _fill_audit(rec: GrcAudit, a: dict) -> None:
    g = _h()
    rec.audit_ref = g._text(a.get("audit_ref"), 50)
    rec.title = str(a.get("title") or rec.audit_ref or "Audit")[:500]
    rec.audit_type, rec.status = g._text(a.get("audit_type"), 32), g._text(a.get("status"), 32)
    rec.framework_code, rec.audit_firm = g._text(a.get("framework_code"), 50), g._text(a.get("audit_firm"), 255)
    for f in ("planned_start", "planned_end", "actual_end", "certification_valid_until"):
        setattr(rec, f, g._date(a.get(f)))
    rec.findings_count, rec.critical_findings = g._int(a.get("findings_count")), g._int(a.get("critical_findings"))
    if isinstance(a.get("findings"), list):
        rec.findings = [_finding(x) for x in a["findings"] if isinstance(x, dict)][:500]


async def _with_details(fetch, rows: list, path: str) -> list:
    """Newest MAX_DETAILS rows get their detail merged in; a failed detail keeps the list row."""
    out = [r for r in rows if isinstance(r, dict) and str(r.get("id", "")).isdigit()]
    for r in out[:MAX_DETAILS]:
        detail = await fetch(f"{path}/{int(r['id'])}")
        if isinstance(detail, dict):
            r.update(detail)
    return out


async def sync_assessments(fetch, db: AsyncSession) -> tuple[int, bool]:
    """(records mirrored, whether this FairTPRM exposes assessments)."""
    g, count, available = _h(), 0, True
    rows = await fetch("/grc/assessments", quiet_404=True)
    if rows is None:
        available = False
    elif isinstance(rows, list):
        count += await g._mirror(db, GrcAssessment, await _with_details(fetch, rows, "/grc/assessments"), _fill_assessment)
    audits = await fetch("/grc/audits")
    if isinstance(audits, list):
        count += await g._mirror(db, GrcAudit, await _with_details(fetch, audits, "/grc/audits"), _fill_audit)
    return count, available
