"""CrowdStrike alerts CTEM keeps without their detail (saved by an early pull, and older than the 30 days each pull
reads) are fetched again by id, so their source addresses, accounts, process tree and actions show up. The shipper
(or the direct connector) asks for the list during its normal CrowdStrike pull; it is a read with the same Alerts API
the pull already uses. Each alert is asked for at most once a week, so one Falcon no longer has isn't asked for forever."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

TRIED_KEY = "cs_alert_refresh_tried"
RETRY = timedelta(days=7)
MAX_IDS = 500


async def due(db: AsyncSession, limit: int = MAX_IDS) -> list[str]:
    """Composite ids of CrowdStrike alerts without detail, not asked for in the last week; marked as asked."""
    from api.core.cs_alert_actions import composite_id
    from api.models.settings import AppSetting
    now = datetime.now(timezone.utc)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == TRIED_KEY))).scalar_one_or_none()
    try:
        tried = json.loads(row.value) if row and row.value else {}
    except ValueError:
        tried = {}
    tried = {k: v for k, v in (tried if isinstance(tried, dict) else {}).items()
             if isinstance(v, str) and v >= (now - RETRY * 4).isoformat()}   # forget old attempts
    out = []
    for r in (await db.execute(select(AppSetting).where(AppSetting.key.like("threat\\_alert\\_%", escape="\\")))).scalars():
        if len(out) >= limit:
            break
        try:
            v = json.loads(r.value) if r.value else {}
        except ValueError:
            continue
        if not isinstance(v, dict) or v.get("source") != "crowdstrike" or v.get("detail_enc"):
            continue
        cid = composite_id(r.key)
        if cid and tried.get(cid, "") < (now - RETRY).isoformat():
            out.append(cid)
            tried[cid] = now.isoformat()
    if out:
        row = row or AppSetting(key=TRIED_KEY, is_sensitive=False)
        row.value = json.dumps(tried)
        db.add(row)
    return out
