"""
FairTPRM connector -- third-party (supplier) risk from open-fairtprm's REST API v2.

Auth: Authorization: Bearer <API token created in FairTPRM>. FairTPRM tokens are
IP-whitelisted, so CTEM's outbound IP must be on the token's allow-list.
Base URL: the FairTPRM root; a trailing /api/v2 is fine too.

What FairTPRM v2 exposes (and what we pull):
  GET /vendors               -> ThirdPartyRisk rows (name, tier, status)
  GET /vendors/{id}/srs      -> latest security rating -> risk score, grade, open high/critical issues
  GET /fair/analyses         -> FAIR loss estimates, attached by vendor name
  GET /grc/*                 -> frameworks, controls, risk register, evidence, monitors (fairtprm_grc.py)
FairTPRM does not expose its Grip ITDR / shadow SaaS / shadow AI data over the API;
use CTEM's Grip connector for those.
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

_PAGE = 200          # FairTPRM caps limit at 200
_MAX_PAGES = 500
_SRS_MAX = 950       # UpGuard-style rating: 950 is best, 0 is worst
_FAIR_LEVEL = {"critical": 90.0, "very high": 90.0, "high": 75.0, "medium": 50.0, "moderate": 50.0,
               "low": 25.0, "very low": 10.0}


UNRATED = "-"


class FairTPRMError(RuntimeError):
    pass


@register(Vendor.fairtprm)
class FairTPRMConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client(timeout=20.0) as client:
                await self._get(client, "/vendors", {"limit": 1})
            return True
        except Exception as exc:
            log.warning("FairTPRM connection test failed: %s", exc)
            return False

    async def sync(self, db: AsyncSession) -> int:
        problems: list[str] = []
        async with safe_client(timeout=60.0) as client:
            vendors = await self._vendors(client)
            fair = await self._fair_by_vendor(client)
            count = 0
            for v in vendors:
                srs = await self._latest_srs(client, v["id"])
                await self._upsert(db, v, srs, fair.get(_norm(v.get("vendor_name"))))
                count += 1
            await db.commit()
            if str(self.config.get("pull_grc", True)).lower() not in ("false", "0", "no", "off"):
                from api.integrations.fairtprm_grc import sync_grc
                grc_count, problems = await sync_grc(self, client, db)
                count += grc_count
        log.info("FairTPRM sync complete: %d records", count)
        if problems:
            # Everything that worked is saved; the card should still say something went wrong
            raise FairTPRMError(f"{count} records synced, but GRC data was incomplete: " + "; ".join(problems)[:400])
        return count

    # ── pulls ─────────────────────────────────────────────────────────────────

    async def _vendors(self, client) -> list[dict]:
        out, offset = [], 0
        for _ in range(_MAX_PAGES):
            body = await self._get(client, "/vendors", {"limit": _PAGE, "offset": offset})
            items = [v for v in (body.get("data") or []) if isinstance(v, dict) and v.get("id") is not None]
            out.extend(items)
            offset += _PAGE
            if not items or offset >= int(body.get("total") or 0):
                break
        return out

    async def _latest_srs(self, client, vendor_id) -> dict | None:
        try:
            rows = (await self._get(client, f"/vendors/{int(vendor_id)}/srs")).get("data") or []
        except FairTPRMError as exc:
            log.info("FairTPRM SRS for vendor %s unavailable: %s", vendor_id, exc)
            return None
        return rows[0] if rows and isinstance(rows[0], dict) else None  # newest first

    async def _fair_by_vendor(self, client) -> dict[str, dict]:
        try:
            rows = (await self._get(client, "/fair/analyses", {"limit": 200})).get("data") or []
        except FairTPRMError as exc:
            log.info("FairTPRM FAIR analyses unavailable: %s", exc)
            return {}
        latest: dict[str, dict] = {}
        for r in rows:  # newest first, so keep the first one per vendor
            if isinstance(r, dict) and r.get("vendor_name"):
                latest.setdefault(_norm(r["vendor_name"]), r)
        return latest

    # ── mapping ───────────────────────────────────────────────────────────────

    async def _upsert(self, db: AsyncSession, v: dict, srs: dict | None, fair: dict | None) -> None:
        from api.models.risk import ThirdPartyRisk

        ext_id = str(v["id"])
        rec = (await db.execute(select(ThirdPartyRisk).where(
            ThirdPartyRisk.source == "fairtprm", ThirdPartyRisk.external_id == ext_id)
            .order_by(ThirdPartyRisk.created_at))).scalars().first()
        if rec is None:
            rec = ThirdPartyRisk(source="fairtprm", external_id=ext_id)
            db.add(rec)
        rec.supplier_name = (str(v.get("vendor_name") or v.get("vendor_domain") or ext_id))[:256]
        tier = str(v.get("vendor_tier") or "").strip()
        rec.tier = f"tier{tier}" if tier in ("1", "2", "3") else (tier[:32] or None)
        rec.status = str(v.get("status") or "")[:32] or None

        score, grade, open_issues, assessed = None, None, 0, None
        if srs:
            rating = _num(srs.get("score"))
            if rating is not None:
                score = round(max(0.0, min(100.0, (_SRS_MAX - rating) / _SRS_MAX * 100)), 1)
            g = str(srs.get("score_grade") or "").strip().upper()[:1]
            grade = g if g in ("A", "B", "C", "D", "F") else None
            open_issues = int(_num(srs.get("critical_risks")) or 0) + int(_num(srs.get("high_risks")) or 0)
            assessed = _parse_dt(srs.get("scored_at"))
        if score is None and fair:
            score = _FAIR_LEVEL.get(str(fair.get("risk_level") or "").strip().lower())
        rec.risk_score = score if score is not None else 0.0
        # No rating and no FAIR analysis means we don't know, which is not the same as "A"
        rec.risk_grade = grade or (_score_to_grade(rec.risk_score) if score is not None else UNRATED)
        rec.open_gaps = open_issues
        rec.last_assessment = assessed or _parse_dt(v.get("updated_at"))
        rec.extra = {
            "domain": v.get("vendor_domain"),
            "rated": score is not None,
            "srs": None if not srs else {k: srs.get(k) for k in (
                "score", "score_grade", "critical_risks", "high_risks", "medium_risks", "low_risks", "scored_at")},
            "fair": None if not fair else {k: fair.get(k) for k in (
                "risk_level", "annualized_loss_expectancy", "created_at")},
        }

    # ── HTTP ──────────────────────────────────────────────────────────────────

    async def _get(self, client, path: str, params: dict | None = None) -> dict:
        r = await client.get(f"{self._api}{path}", headers=self._headers(), params=params or {})
        if r.status_code == 200:
            body = r.json()
            return body if isinstance(body, dict) else {"data": body}
        reason = ""
        try:
            reason = str((r.json() or {}).get("error") or "")[:120]
        except ValueError:
            pass
        hint = {401: "FairTPRM rejected the API token (wrong token, expired, or CTEM's IP isn't on the token's IP whitelist)",
                403: "the FairTPRM token has no access to the TPRM module"}.get(r.status_code, f"FairTPRM returned HTTP {r.status_code}")
        raise FairTPRMError(f"{hint}{f': {reason}' if reason else ''}")

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.config['api_key']}", "Accept": "application/json"}

    @property
    def _api(self) -> str:
        """Accept https://tprm.acme.example, .../api, or .../api/v2 (or a stale /api/v1)."""
        base = self.config["base_url"].strip().rstrip("/")
        for suffix in ("/api/v2", "/api/v1", "/api"):
            if base.lower().endswith(suffix):
                base = base[: -len(suffix)]
                break
        return f"{base}/api/v2"


# ── Pure helpers ──────────────────────────────────────────────────────────────

def _norm(name) -> str:
    return " ".join(str(name or "").lower().split())


def _num(val) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _score_to_grade(score: float) -> str:
    if score >= 80:
        return "F"
    if score >= 60:
        return "D"
    if score >= 40:
        return "C"
    if score >= 20:
        return "B"
    return "A"


def _parse_dt(s) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00").replace(" ", "T"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
