"""Supplier security score history from FairTPRM (api/core/tprm_scores.py), for quarter-by-quarter KPIs.

GET /vendors/score-history gives every UpGuard, Shodan and custom score with its date (newer FairTPRM). A FairTPRM
without it answers 404: then CTEM records each supplier's combined percentage once a day from its vendor record, so
the quarters from now on still have a number, and keeps asking for the history on later syncs."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from api.core import tprm_scores as ts

log = logging.getLogger("open-ctem.fairtprm")
PAGE, MAX_PAGES = 100, 50


async def sync_scores(conn, client, db) -> int:
    from api.integrations.fairtprm import FairTPRMError
    from api.models.risk import ThirdPartyRisk, ThirdPartyScore
    suppliers = {ext: str(i) for ext, i in (await db.execute(select(ThirdPartyRisk.external_id, ThirdPartyRisk.id).where(
        ThirdPartyRisk.source == "fairtprm"))).all()}
    if not suppliers:
        return 0
    since = f"{datetime.now(timezone.utc).year - 1}-01-01"
    n = 0
    try:
        for page in range(MAX_PAGES):
            body = await conn._get(client, "/vendors/score-history", {"since": since, "limit": PAGE, "offset": page * PAGE})
            n += await ts.ingest(db, body, suppliers)
            await db.commit()
            if len(body.get("data") or []) < PAGE:
                break
        return n
    except FairTPRMError as e:
        if e.status != 404:
            log.warning("FairTPRM score history unavailable: %s", e)
            return n
    # No history endpoint yet: today's combined percentage, once a day
    day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    if (await db.execute(select(ThirdPartyScore.id).where(ThirdPartyScore.kind == "combined", ThirdPartyScore.at >= day).limit(1))).first():
        return 0
    for ext, sid in suppliers.items():
        try:
            v = (await conn._get(client, f"/vendors/{int(ext)}")).get("data") or {}
        except (FairTPRMError, ValueError) as e:
            log.info("FairTPRM vendor %s unavailable for its score: %s", ext, e)
            continue
        n += int(await ts.record_today(db, sid, v if isinstance(v, dict) else {}))
    await db.commit()
    log.info("FairTPRM has no score history yet; recorded today's score for %d suppliers", n)
    return n
