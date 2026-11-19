"""Splunk connector. Pulls alerts and pushes enriched risk context."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.splunk")


@register(Vendor.splunk)
class SplunkConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/services/server/info",
                    auth=(self.config["username"], self.config["password"]),
                    params={"output_mode": "json"},
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("Splunk test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        alerts = await self._fetch_notable_events()
        await self._cache_threats(alerts, db)
        return len(alerts)

    async def push_risk_context(self, payload: dict) -> None:
        """Push device risk context into Splunk as a custom event via HEC."""
        hec_url = self.config.get("hec_url")
        hec_token = self.config.get("hec_token")
        if not hec_url or not hec_token:
            log.warning("Splunk HEC not configured -- cannot push")
            return
        async with safe_client() as client:
            await client.post(
                hec_url,
                headers={"Authorization": f"Splunk {hec_token}"},
                json={"sourcetype": "open-ctem:risk", "event": payload},
            )

    async def _fetch_notable_events(self) -> list[dict]:
        """Run a saved search or SPL query for notable events."""
        query = self.config.get("notable_query", "search index=notable earliest=-24h | head 500")
        async with safe_client() as client:
            # Kick off search job
            resp = await client.post(
                f"{self._base}/services/search/jobs",
                auth=(self.config["username"], self.config["password"]),
                data={"search": query, "output_mode": "json", "exec_mode": "oneshot", "count": 500},
            )
            resp.raise_for_status()
        results = resp.json().get("results", [])
        return results

    async def _cache_threats(self, events: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json

        for ev in events[:200]:
            key = f"threat_alert_splunk_{ev.get('_serial', ev.get('event_id', ''))}"
            payload = {
                "source": "splunk",
                "id": key,
                "severity": ev.get("urgency", ""),
                "hostname": ev.get("dest", ev.get("src")),
                "description": ev.get("search_name") or ev.get("description"),
                "raw": {k: v for k, v in ev.items() if not k.startswith("_")},
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()

    @property
    def _base(self) -> str:
        host = self.config["host"]
        port = self.config.get("port", 8089)
        return f"https://{host}:{port}"
