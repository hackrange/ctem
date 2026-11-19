"""
FairTPRM connector -- Third Party Risk Management.

Pulls supplier risk assessments and control gaps from open-fairtprm
(git.hackrange.com/trice/open-fairtprm).

NOTE: If FairTPRM itself has the Grip Security integration configured, Grip's
ITDR/posture/shadow-SaaS telemetry already flows through FairTPRM's data model.
In that case set fairtprm_grip_passthrough=true on the open-ctem Grip connector
to avoid double-counting identity risk signals.

Auth: API key in X-API-Key header.
Base URL: tenant root, e.g. https://tprm.acme.example.com
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
    Syncs third-party risk data from FairTPRM:
      - Supplier records -> ThirdPartyRisk (upsert by source + external_id)
      - Control gaps     -> ThirdPartyControlGap (upsert by source + external_id)
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
        log.info("FairTPRM sync complete: %d records", total)
        return total

    # ── Suppliers + control gaps ──────────────────────────────────────────────

    async def _sync_suppliers(self, db: AsyncSession) -> int:
        from api.models.risk import ThirdPartyControlGap, ThirdPartyRisk

        suppliers = await self._paginate("/api/v1/suppliers")
        count = 0

        for s in suppliers:
            ext_id = str(s.get("id", ""))
            if not ext_id:
                continue

            result = await db.execute(
                select(ThirdPartyRisk).where(
                    ThirdPartyRisk.source == "fairtprm",
                    ThirdPartyRisk.external_id == ext_id,
                )
            )
            rec = result.scalar_one_or_none() or ThirdPartyRisk(
                source="fairtprm", external_id=ext_id
            )

            rec.supplier_name = s.get("name") or s.get("companyName") or ext_id
            rec.tier = str(s.get("tier") or "")[:32] or None
            rec.status = str(s.get("status") or "")[:32] or None
            rec.risk_score = min(100.0, float(s.get("riskScore") or s.get("risk_score") or 0))
            rec.risk_grade = _score_to_grade(rec.risk_score)
            rec.last_assessment = _parse_dt(s.get("lastAssessmentDate") or s.get("last_assessment_date"))
            rec.next_review = _parse_dt(s.get("nextReviewDate") or s.get("next_review_date"))

            db.add(rec)
            await db.flush()  # get rec.id for FK in gaps

            # Sync control gaps for this supplier
            gaps = s.get("controlGaps") or s.get("control_gaps") or []
            gap_count = 0
            for g in gaps:
                gap_ext = str(g.get("id") or g.get("controlId") or "")
                if not gap_ext:
                    continue
                g_result = await db.execute(
                    select(ThirdPartyControlGap).where(
                        ThirdPartyControlGap.source == "fairtprm",
                        ThirdPartyControlGap.external_id == f"{ext_id}:{gap_ext}",
                    )
                )
                gap_rec = g_result.scalar_one_or_none() or ThirdPartyControlGap(
                    source="fairtprm",
                    external_id=f"{ext_id}:{gap_ext}",
                    supplier_id=rec.id,
                )
                gap_rec.control_name = g.get("controlName") or g.get("name") or "Unknown control"
                gap_rec.description = g.get("description") or ""
                gap_rec.severity = _map_severity(g.get("severity") or g.get("risk") or "medium")
                gap_rec.is_resolved = str(g.get("status") or "").lower() in ("resolved", "closed", "passed")
                gap_rec.detected_at = _parse_dt(g.get("detectedAt") or g.get("createdAt"))
                db.add(gap_rec)
                gap_count += 1

            rec.open_gaps = sum(1 for g in gaps if str(g.get("status") or "").lower() not in ("resolved", "closed", "passed"))
            count += 1 + gap_count

        await db.commit()
        log.info("FairTPRM: synced %d suppliers with control gaps", sum(1 for s in suppliers if s.get("id")))
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


# ── Pure helpers ──────────────────────────────────────────────────────────────

def _score_to_grade(score: float) -> str:
    if score >= 80: return "F"
    if score >= 60: return "D"
    if score >= 40: return "C"
    if score >= 20: return "B"
    return "A"


def _map_severity(raw: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "low"}.get(raw.lower(), "medium")


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
