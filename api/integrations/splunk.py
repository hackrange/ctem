"""Splunk connector. Pulls alerts and pushes enriched risk context."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.splunk")


def legacy_ssl_mode(config: dict) -> str:
    """What an integration with no ssl_mode gets: kept for ones saved before the setting existed. New ones
    are given "https" (verify) when created (api/routes/integrations.py)."""
    if str(config.get("base_url", "")).startswith("http://") or config.get("no_ssl"):
        return "http"
    return "https_no_verify"


def new_ssl_mode(config: dict) -> str:
    """The SSL mode a new integration that didn't pick one starts with: verify the certificate."""
    return "http" if legacy_ssl_mode(config) == "http" else "https"


@register(Vendor.splunk)
class SplunkConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client(verify=self._verify) as client:
                resp = await client.get(
                    f"{self._base}/services/server/info",
                    auth=(self._username, self._password),
                    params={"output_mode": "json"},
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("Splunk test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        self.warnings: list[str] = []
        if self.legacy_no_verify:
            self.warnings.append("the Splunk certificate is not checked (SSL mode was never set); pick "
                                 "HTTPS (verify cert) once Splunk has a trusted certificate")
        alerts = await self._fetch_notable_events()
        await self._cache_threats(alerts, db)
        # Map what lives where first: the catalog is built from that map
        from api.hunt.schema import refresh_schema
        await refresh_schema(self, db)
        await self._refresh_spl_catalog(db)
        return len(alerts)

    async def push_risk_context(self, payload: dict) -> None:
        """Push device risk context into Splunk as a custom event via HEC."""
        hec_url = self.config.get("hec_url")
        hec_token = self.config.get("hec_token")
        if not hec_url or not hec_token:
            log.warning("Splunk HEC not configured -- cannot push")
            return
        async with safe_client(verify=self._verify) as client:
            await client.post(
                hec_url,
                headers={"Authorization": f"Splunk {hec_token}"},
                json={"sourcetype": "open-ctem:risk", "event": payload},
            )

    async def run_search(self, spl: str, earliest: str = "-7d", latest: str = "now",
                         max_rows: int = 200) -> list[dict]:
        """Run one already-vetted SPL search and hand back its result rows."""
        params = {
            "search": spl, "output_mode": "json", "exec_mode": "oneshot",
            "count": max_rows, "earliest_time": earliest, "latest_time": latest,
        }
        async with safe_client(verify=self._verify) as client:
            resp = await client.post(
                f"{self._base}/services/search/jobs",
                auth=(self._username, self._password), data=params, timeout=90.0,
            )
            resp.raise_for_status()
        return resp.json().get("results", [])[:max_rows]

    async def list_indexes(self) -> list[dict]:
        return await self._list_indexes()

    async def _fetch_notable_events(self) -> list[dict]:
        """Run the configured SPL query with a rolling lookback window."""
        lookback = int(self.config.get("lookback_minutes", 5))
        max_events = int(self.config.get("max_events", 500))
        query = self.config.get(
            "notable_query",
            "search index=wineventlog OR index=crowdstrike OR index=guardicore | table _time, host, source, _raw",
        )
        # Ensure the query starts with 'search' for the REST API
        if not query.lstrip().lower().startswith("search"):
            query = f"search {query}"

        job_params: dict = {
            "search": query,
            "output_mode": "json",
            "exec_mode": "oneshot",
            "count": max_events,
        }
        # Inject lookback as job-level time range only when the SPL has no inline earliest=
        if "earliest=" not in query and "earliest_time=" not in query:
            job_params["earliest_time"] = f"-{lookback}m@m"
            job_params["latest_time"] = "now"

        async with safe_client(verify=self._verify) as client:
            resp = await client.post(
                f"{self._base}/services/search/jobs",
                auth=(self._username, self._password),
                data=job_params,
                timeout=60.0,
            )
            resp.raise_for_status()
        results = resp.json().get("results", [])
        log.debug("Splunk fetch: lookback=%dm max=%d got=%d", lookback, max_events, len(results))
        return results

    async def _cache_threats(self, events: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json

        import hashlib
        # Only real notables become alerts; raw events are searched live by the hunt
        events = [e for e in events if e.get("search_name") or e.get("urgency") or e.get("description")]
        for ev in events[:200]:
            # _serial is just the row number in this search, so hash the event itself
            ident = ev.get("event_id") or hashlib.sha256(
                f"{ev.get('_time')}|{ev.get('host')}|{ev.get('_raw')}".encode()
            ).hexdigest()[:32]
            key = f"threat_alert_splunk_{ident}"
            payload = {
                "source": "splunk",
                "id": key,
                "severity": ev.get("urgency", ""),
                "hostname": ev.get("dest") or ev.get("src") or ev.get("host"),
                "description": ev.get("search_name") or ev.get("description"),
                "raw": {k: v for k, v in ev.items() if not k.startswith("_")},
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()

    async def _refresh_spl_catalog(self, db: AsyncSession, indexes: list[dict] | None = None) -> None:
        """
        Introspect Splunk indexes and auto-generate a SOC-ready SPL search catalog.
        Stores the result as 'splunk_spl_catalog' AppSetting (consumed by /hunt/splunk/catalog).
        """
        import json
        if indexes is None:
            indexes = await self._list_indexes()
        from api.hunt.catalog import build_spl_catalog
        from api.hunt.schema import load_schema
        catalog = build_spl_catalog(indexes, await load_schema(db))
        from api.models.settings import AppSetting
        from sqlalchemy import select
        result = await db.execute(select(AppSetting).where(AppSetting.key == "splunk_spl_catalog"))
        setting = result.scalar_one_or_none() or AppSetting(key="splunk_spl_catalog", is_sensitive=False)
        setting.value = json.dumps(catalog)
        db.add(setting)
        await db.commit()
        log.info("SPL catalog rebuilt: %d searches", len(catalog))

    async def _list_indexes(self) -> list[dict]:
        async with safe_client(verify=self._verify) as client:
            resp = await client.get(
                f"{self._base}/services/data/indexes",
                auth=(self._username, self._password),
                params={"output_mode": "json", "count": 100},
            )
        if resp.status_code != 200:
            return []
        entries = resp.json().get("entry", [])
        indexes = []
        for e in entries:
            content = e.get("content", {})
            indexes.append({
                "name": e.get("name"),
                "totalEventCount": content.get("totalEventCount", 0),
                "currentDBSizeMB": content.get("currentDBSizeMB", 0),
                "minTime": content.get("minTime"),
                "maxTime": content.get("maxTime"),
            })
        return indexes

    @property
    def _ssl_mode(self) -> str:
        """
        ssl_mode values:
          'https'          -- HTTPS + verify cert (default for new configs)
          'https_no_verify' -- HTTPS + skip cert check (self-signed certs)
          'http'           -- plain HTTP, no TLS
        Legacy: if unset, infer from base_url scheme (https -> https_no_verify for compat,
        since most self-managed Splunk instances use self-signed certs).
        """
        mode = self.config.get("ssl_mode", "")
        if mode in ("https", "https_no_verify", "http"):
            return mode
        return legacy_ssl_mode(self.config)

    @property
    def legacy_no_verify(self) -> bool:
        """An integration saved before SSL mode existed: it keeps working unverified, and its card says so."""
        return self.config.get("ssl_mode", "") not in ("https", "https_no_verify", "http") \
            and self._ssl_mode == "https_no_verify"

    @property
    def _verify(self) -> bool:
        return self._ssl_mode == "https"

    @property
    def _base(self) -> str:
        scheme = "http" if self._ssl_mode == "http" else "https"
        # Accept either a full base_url from the UI or host+port separately
        if "base_url" in self.config:
            url = self.config["base_url"].rstrip("/")
            if url.endswith("/services"):
                url = url[:-9]
            # Normalize scheme to match ssl_mode
            if url.startswith("http://") or url.startswith("https://"):
                url = scheme + "://" + url.split("://", 1)[1]
            return url
        host = self.config["host"]
        port = self.config.get("port", 8089)
        return f"{scheme}://{host}:{port}"

    @property
    def _username(self) -> str:
        return self.config.get("username") or self.config.get("user", "admin")

    @property
    def _password(self) -> str:
        return self.config.get("password") or self.config.get("api_key", "")
