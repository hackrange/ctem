"""Rapid7 InsightCloudSec (CSPM) connector: Insight findings per cloud account, read with GET only."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations import rapid7_cloudsec_store as store
from api.integrations import rapid7_common as r7
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-cloudsec")

_SEVERITY_NAMES = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_MAX_PAGES = 4000  # per account, 500 rows a page; a runaway cursor stops here


class CloudSecError(RuntimeError):
    """A tenant answer we can't build a complete picture from."""


@register(Vendor.rapid7_cloudsec)
class InsightCloudSecConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            # No redirects: a bad key or wrong host bounces to the Rapid7 login page with a cheerful 200
            async with safe_client() as client:
                resp = await client.get(f"{self._base}/public/clouds/list", headers=self._headers(),
                                        follow_redirects=False)
            return resp.status_code == 200 and "json" in resp.headers.get("content-type", "")
        except Exception as e:
            log.warning("CloudSec test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        self.warnings: list[str] = []
        started = datetime.now(timezone.utc)
        cap = r7.int_cfg(self.config, "max_findings", 0, 0, 10_000_000)  # 0 = no limit
        async with safe_client(timeout=120.0) as client:
            insights = await self._insights(client)
            clouds, listed_all = await self._clouds(client)
            saver = await store.Saver.load(db, started)
            done: set[str] = set()   # accounts read to the last page, safe to close what they no longer list
            failed = 0
            for cloud in clouds:
                if not await store.still_enabled(db, getattr(self, "integration_id", None)):
                    self.warnings.append("the integration was disabled mid-run, so the rest was skipped")
                    return saver.count
                room = (cap - saver.count) if cap else None
                if room is not None and room <= 0:
                    break
                try:
                    complete = await self._read_account(client, cloud, insights, saver, room)
                except CloudSecError as e:
                    failed += 1
                    log.warning("CloudSec account %s skipped: %s", cloud, e)
                    continue
                if complete:
                    done.add(cloud)
        if clouds and failed == len(clouds):
            raise CloudSecError(f"InsightCloudSec refused every cloud account ({failed}); nothing was imported")
        if failed:
            self.warnings.append(f"{failed} of {len(clouds)} cloud accounts could not be read and were skipped")
        if cap and saver.count >= cap:
            self.warnings.append(f"stopped at the {cap} finding cap, so nothing was closed")
        else:
            closed = await saver.close_missing(done, set(clouds) if listed_all else None)
            log.info("CloudSec sync: %d findings, %d closed, %d accounts", saver.count, closed, len(done))
        return saver.count

    @property
    def _base(self) -> str:
        # InsightCloudSec lives on a per-tenant host, not the Insight Platform gateway
        base = str(self.config.get("base_url") or "").rstrip("/")
        if base.endswith("/v2"):
            base = base[:-3]
        if not base.startswith("https://"):
            raise ValueError("InsightCloudSec needs base_url like https://us1.cloudsec.insight.rapid7.com")
        return f"{base}/v2"

    @property
    def _root(self) -> str:
        return self._base[:-3]

    def _headers(self) -> dict:
        return {"Api-Key": self.config["api_key"], "Accept": "application/json"}

    def _min_severity(self) -> int:
        raw = str(self.config.get("min_severity", "high")).lower()
        return _SEVERITY_NAMES.get(raw, 4)

    async def _get(self, client, url: str, params: dict | None = None) -> dict | list:
        # GET only: this connector never changes anything in the tenant
        resp = await client.get(url, headers=self._headers(), params=params, follow_redirects=False)
        if resp.status_code != 200 or "json" not in resp.headers.get("content-type", ""):
            hint = " (the key was refused)" if resp.status_code in (301, 302, 303, 401, 403) else ""
            raise CloudSecError(f"HTTP {resp.status_code}{hint}")
        return resp.json()

    async def _insights(self, client) -> dict[str, dict]:
        """Insights at or above the severity floor, keyed the way findings name them ("backoffice:59")."""
        body = await self._get(client, f"{self._base}/public/insights/list")
        rows = body if isinstance(body, list) else body.get("insights", [])
        floor = self._min_severity()
        out = {}
        for i in rows:
            if i.get("insight_id") is None or i.get("disabled"):
                continue
            sev = int(i.get("custom_severity") or i.get("severity") or 0)
            if sev >= floor:
                out[f"{i.get('source') or 'backoffice'}:{i['insight_id']}"] = {**i, "severity": sev}
        return out

    async def _clouds(self, client) -> tuple[list[str], bool]:
        """Cloud account ids, and whether the list is the whole set (so a missing account was removed)."""
        body = await self._get(client, f"{self._base}/public/clouds/list")
        rows = body.get("clouds", []) if isinstance(body, dict) else body
        ids = [str(int(c["id"])) for c in rows if str(c.get("id", "")).isdigit()]
        total = body.get("total_count") if isinstance(body, dict) else None
        return ids, total is not None and int(total) == len(ids)

    async def _read_account(self, client, cloud: str, insights: dict, saver, room: int | None) -> bool:
        """Every page of one account's findings. True when it read to the end, uncapped."""
        url = f"{self._root}/v4/insights/findings-per-cloud/{cloud}/"   # no slash = 308 to another host
        cursor, seen_cursors, taken = None, set(), 0
        for _ in range(_MAX_PAGES):
            page = await self._get(client, url, {"cursor": cursor} if cursor else None)
            rows = [r for r in page.get("results", []) if r.get("insight_id") in insights and r.get("resource_id")]
            if room is not None:
                rows = rows[:max(room - taken, 0)]
            taken += len(rows)
            await saver.save(rows, insights)
            if room is not None and taken >= room:
                return False
            cursor = page.get("next_cursor")
            if not cursor or not page.get("results"):
                return True
            if cursor in seen_cursors:
                raise CloudSecError("the next-page cursor repeated")
            seen_cursors.add(cursor)
        raise CloudSecError(f"more than {_MAX_PAGES} pages")
