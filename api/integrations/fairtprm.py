"""
FairTPRM connector -- Third Party Risk Management.

Pulls supplier risk assessments, control gaps, and questionnaire responses
from open-fairtprm (git.hackrange.com/trice/open-fairtprm).

NOTE: If FairTPRM itself has the Grip Security integration configured, Grip's
ITDR/posture/shadow-SaaS telemetry already flows through FairTPRM's data model.
In that case the open-ctem Grip connector (fairtprm_grip_passthrough=true) can
be disabled to avoid double-counting identity risk signals.

Auth: API key in X-API-Key header.
Base URL: configured as base_url in integration config.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.fairtprm")

_PAGE = 100


@register(Vendor.fairtprm)
class FairTPRMConnector(BaseConnector):
    """
    Syncs third-party risk findings from FairTPRM into the GRC risk model.
    Each supplier assessment creates or updates a GRC risk record keyed by
    (source=fairtprm, external_id=supplier_id).
    """

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                r = await client.get(
                    f"{self._base}/api/v1/health",
                    headers=self._headers(),
                )
            return r.status_code == 200
        except Exception as exc:
            log.warning("FairTPRM connection test failed: %s", exc)
            return False

    async def sync(self, db: AsyncSession) -> int:
        total = 0
        total += await self._sync_suppliers(db)
        total += await self._sync_assessments(db)
        log.info("FairTPRM sync complete: %d records", total)
        return total

    # ── Suppliers ─────────────────────────────────────────────────────────────

    async def _sync_suppliers(self, db: AsyncSession) -> int:
        from api.models.risk import RiskScore, RiskScoreHistory

        suppliers = await self._paginate("/api/v1/suppliers")
        count = 0
        for s in suppliers:
            ext_id = str(s.get("id", ""))
            if not ext_id:
                continue

            result = await db.execute(
                select(RiskScore).where(
                    RiskScore.entity_type == "third_party",
                    RiskScore.entity_id == ext_id,
                )
            )
            rec = result.scalar_one_or_none() or RiskScore(
                entity_type="third_party", entity_id=ext_id
            )

            risk_score = float(s.get("riskScore") or s.get("risk_score") or 0)
            rec.score = min(100.0, risk_score)
            rec.grade = _score_to_grade(rec.score)
            rec.calculated_at = datetime.now(timezone.utc)
            rec.metadata = {
                "supplier_name": s.get("name"),
                "tier": s.get("tier"),
                "status": s.get("status"),
                "source": "fairtprm",
            }
            db.add(rec)
            db.add(RiskScoreHistory(
                entity_type="third_party",
                entity_id=ext_id,
                score=rec.score,
                grade=rec.grade,
                recorded_at=rec.calculated_at,
            ))
            count += 1

        await db.commit()
        log.info("FairTPRM suppliers: upserted %d", count)
        return count

    # ── Assessments / control gaps ────────────────────────────────────────────

    async def _sync_assessments(self, db: AsyncSession) -> int:
        from api.models.vuln import Finding, FindingStatus, Vuln

        assessments = await self._paginate("/api/v1/assessments")
        count = 0
        for a in assessments:
            # Each failed control creates a GRC-type finding
            for gap in a.get("controlGaps") or a.get("control_gaps") or []:
                ext_id = f"fairtprm-{a.get('id')}-{gap.get('controlId','?')}"
                result = await db.execute(
                    select(Finding).where(
                        Finding.source == "fairtprm",
                        Finding.source_finding_id == ext_id,
                    )
                )
                f = result.scalar_one_or_none() or Finding(
                    source="fairtprm",
                    source_finding_id=ext_id,
                    status=FindingStatus.open,
                )

                f.title = gap.get("controlName") or "FairTPRM control gap"
                f.description = gap.get("description") or ""
                f.severity = _map_severity(gap.get("severity") or gap.get("risk") or "medium")
                f.last_seen = datetime.now(timezone.utc)
                db.add(f)
                count += 1

        await db.commit()
        log.info("FairTPRM control gaps: upserted %d findings", count)
        return count

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    async def _paginate(self, path: str) -> list[dict]:
        results: list[dict] = []
        page = 1
        for _ in range(500):
            async with safe_client() as client:
                r = await client.get(
                    f"{self._base}{path}",
                    headers=self._headers(),
                    params={"page": page, "per_page": _PAGE},
                )
            if r.status_code != 200:
                log.warning("FairTPRM %s returned %d", path, r.status_code)
                break
            data = r.json()
            items = data if isinstance(data, list) else (data.get("data") or data.get("items") or [])
            if not items:
                break
            results.extend(items)
            if len(items) < _PAGE:
                break
            page += 1
        return results

    def _headers(self) -> dict:
        return {"X-API-Key": self.config["api_key"], "Accept": "application/json"}

    @property
    def _base(self) -> str:
        return self.config["base_url"].rstrip("/")


def _score_to_grade(score: float) -> str:
    if score >= 80: return "F"
    if score >= 60: return "D"
    if score >= 40: return "C"
    if score >= 20: return "B"
    return "A"


def _map_severity(raw: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "low"}.get(raw.lower(), "medium")
