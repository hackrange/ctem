"""FairTPRM's Shadow SaaS / Shadow AI app inventory, for CTEM's shadow checks when Grip isn't connected here.

Needs FairTPRM's GET /api/v2/shadow-saas/apps. A 404 there (older FairTPRM) or a 403 (token user can't
view Shadow SaaS) leaves the old rows alone and records nothing, so the checks say "no data", never "pass".
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.fairtprm")
SOURCE = "fairtprm"
MARKER = "fairtprm:shadow_saas"     # SyncJob vendor the shadow checks treat as a fresh source
_PAGE = 1000
_MAX_PAGES = 200
_SANCTIONED = {"sanctioned", "approved"}


def _level(score: float | None) -> str:
    from api.integrations.grip import _score_to_level
    return _score_to_level(int(score or 0))


def _fill(rec, a: dict) -> None:
    from api.integrations.fairtprm_grc import _dt, _int, _num, _text
    ai = (_text(a.get("ai_depth_level"), 64) or "").strip()
    rec.app_name = _text(a.get("name"), 256) or _text(a.get("domain"), 256) or "Unknown app"
    rec.vendor = _text(a.get("domain"), 256)
    rec.is_shadow_ai = bool(ai) and ai.lower() != "no ai"
    rec.app_category = "ai" if rec.is_shadow_ai else (_text(a.get("category"), 64) or "saas")
    rec.is_sanctioned = (str(a.get("sanction_tag") or "").lower() in _SANCTIONED) or a.get("status") == "onboarded"
    rec.risk_score = _num(a.get("risk_score"))
    rec.risk_level = _level(rec.risk_score)
    rec.user_count = max(0, _int(a.get("users")))
    rec.last_seen = _dt(a.get("last_seen")) or _dt(a.get("updated_at"))


async def sync_shadow(conn, client, db: AsyncSession) -> tuple[int, str]:
    """(apps mirrored, outcome): outcome is ok, unavailable (404) or denied (403)."""
    from api.integrations.fairtprm import FairTPRMError
    from api.models.identity import SaasAppRecord

    rows, offset = [], 0
    try:
        for _ in range(_MAX_PAGES):
            body = await conn._get(client, "/shadow-saas/apps", {"limit": _PAGE, "offset": offset})
            page = [r for r in body.get("data") or [] if isinstance(r, dict) and str(r.get("id", "")).isdigit()]
            rows.extend(page)
            offset += _PAGE
            if len(page) < _PAGE or offset >= int(body.get("total") or 0):
                break
    except FairTPRMError as exc:
        if exc.status in (403, 404):
            log.info("FairTPRM Shadow SaaS not available (HTTP %s); leaving shadow data alone", exc.status)
            return 0, "denied" if exc.status == 403 else "unavailable"
        raise

    started = datetime.now(timezone.utc)
    have = {r.external_id: r for r in (await db.execute(select(SaasAppRecord).where(SaasAppRecord.source == SOURCE))).scalars()}
    seen = set()
    for a in rows:
        if a.get("status") == "dismissed":
            continue  # someone in FairTPRM ruled it out
        ext = str(a["id"])
        rec = have.get(ext)
        if rec is None:
            rec = SaasAppRecord(source=SOURCE, external_id=ext, app_name="", risk_level="low")
            db.add(rec)
            have[ext] = rec
        _fill(rec, a)
        seen.add(ext)
    gone = set(have) - seen
    if gone:
        await db.execute(delete(SaasAppRecord).where(SaasAppRecord.source == SOURCE, SaasAppRecord.external_id.in_(gone)))
    await _mark_fresh(db, conn, started, len(seen))
    return len(seen), "ok"


async def _mark_fresh(db: AsyncSession, conn, started: datetime, n: int) -> None:
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    iid = getattr(conn, "integration_id", None)
    if not iid:
        cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.fairtprm))).scalars().first()
        iid = str(cfg.id) if cfg else ""
    db.add(SyncJob(integration_id=str(iid)[:36], vendor=MARKER, status=SyncStatus.success, started_at=started,
                   finished_at=datetime.now(timezone.utc), records_imported=n))
