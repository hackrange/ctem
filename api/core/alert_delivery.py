"""Send CTEM's alert feed (api/core/alert_feed.py) straight to Splunk HEC, for a Splunk integration with a HEC URL
CTEM can reach (Splunk Cloud, say). An internal Splunk gets the feed through the shipper instead. Each integration
keeps its own position in the feed, so nothing is sent twice or skipped."""
from __future__ import annotations

import json
import logging
import time
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.alert_delivery")


def _hec(url: str) -> str | None:
    u = urlsplit((url or "").strip())
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        return None
    return f"https://{u.netloc}/services/collector/event"


async def deliver(db: AsyncSession) -> int:
    from api.core import alert_feed
    from api.core.ssrf import safe_client
    from api.integrations.base import is_collector_fed
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AppSetting
    sent = 0
    for cfg in (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.splunk,
                                                                 IntegrationConfig.is_enabled.is_(True)))).scalars():
        c = cfg.config or {}
        url, token = _hec(c.get("hec_url") or ""), c.get("hec_token")
        if not url or not token or is_collector_fed(cfg):
            continue
        key = f"alert_feed.cursor.{cfg.id}"
        row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
        if row is None:   # first time: start from now, don't replay history
            db.add(AppSetting(key=key, value=str(await alert_feed.latest_seq(db))))
            await db.commit()
            continue
        rows = await alert_feed.after(db, int(row.value or 0), 500)
        if not rows:
            continue
        body = "\n".join(json.dumps({"time": time.time(), "source": "open-ctem", "sourcetype": "ctem:alert", "event": r.event},
                                    separators=(",", ":")) for r in rows)
        try:
            async with safe_client(timeout=30.0) as client:
                r = await client.post(url, content=body, headers={"Authorization": f"Splunk {token}"})
            if r.status_code != 200:
                log.warning("Splunk HEC for integration %s answered %s", cfg.id, r.status_code)
                continue
        except Exception:  # noqa: BLE001 -- unreachable now; the cursor stays, so the next run sends these again
            log.warning("Splunk HEC for integration %s unreachable", cfg.id)
            continue
        row.value = str(rows[-1].seq)
        await db.commit()
        sent += len(rows)
    return sent
