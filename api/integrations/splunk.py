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
        alerts = await self._fetch_notable_events()
        await self._cache_threats(alerts, db)
        # Rebuild SPL catalog from index introspection on each sync
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

    async def _refresh_spl_catalog(self, db: AsyncSession) -> None:
        """
        Introspect Splunk indexes and auto-generate a SOC-ready SPL search catalog.
        Stores the result as 'splunk_spl_catalog' AppSetting (consumed by /hunt/splunk/catalog).
        """
        import json
        indexes = await self._list_indexes()
        catalog = _build_spl_catalog(indexes)
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
        # Legacy: derive from base_url scheme
        url = self.config.get("base_url", "")
        if url.startswith("http://") or self.config.get("no_ssl"):
            return "http"
        return "https_no_verify"  # safe default for self-managed Splunk

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


def _build_spl_catalog(indexes: list[dict]) -> list[dict]:
    """
    Generate pre-built SPL searches tailored to what actually exists in Splunk.
    SOC team gets copy-paste-ready searches based on real index names.
    """
    catalog = []
    index_names = [i["name"] for i in indexes if i.get("name")]

    # Add universal searches first
    catalog.extend(_UNIVERSAL_SEARCHES)

    # Generate per-index searches for known security-relevant indexes
    security_patterns = {
        "notable": "Notable events (ESCU) -- highest priority SOC queue",
        "main": "Default index -- miscellaneous events",
        "windows": "Windows event logs -- auth, process, network",
        "linux_secure": "Linux auth and sudo events",
        "syslog": "Network device syslogs",
        "firewall": "Firewall allow/deny events",
        "web": "Web access logs",
        "endpoint": "Endpoint telemetry",
        "network": "Network flow data",
        "dns": "DNS query logs",
        "email": "Email security events",
    }

    for idx in index_names:
        for pattern, label in security_patterns.items():
            if pattern in idx.lower():
                catalog.append({
                    "category": "index-specific",
                    "index": idx,
                    "title": f"{label} [{idx}]",
                    "spl": f'index={idx} earliest=-24h | stats count by sourcetype | sort -count',
                    "description": f"Overview of event types in index={idx} over last 24h",
                })
                break

    return catalog


_UNIVERSAL_SEARCHES = [
    {
        "category": "threat-hunting",
        "title": "Failed logins -- brute force candidates",
        "spl": 'index=* (EventCode=4625 OR "Failed password" OR "authentication failure") earliest=-1h | stats count by src_ip, user | where count > 10 | sort -count',
        "description": "Sources with 10+ failed logins in the last hour",
    },
    {
        "category": "threat-hunting",
        "title": "Lateral movement -- unusual RDP/SMB",
        "spl": 'index=* (EventCode=4624 OR EventCode=4648) LogonType IN (3, 10) earliest=-4h | stats count by src_ip, dest_host, user | where count > 3 | sort -count',
        "description": "Network logons (type 3/10) from unusual sources",
    },
    {
        "category": "threat-hunting",
        "title": "New scheduled tasks or services",
        "spl": 'index=* (EventCode=4698 OR EventCode=7045) earliest=-24h | table _time, host, TaskName, ServiceName, CommandLine',
        "description": "Persistence: scheduled task or service creation",
    },
    {
        "category": "threat-hunting",
        "title": "Process injection indicators",
        "spl": 'index=* (EventCode=8 OR "CreateRemoteThread" OR "WriteProcessMemory") earliest=-4h | table _time, host, SourceImage, TargetImage, StartAddress',
        "description": "Sysmon event 8: remote thread injection attempts",
    },
    {
        "category": "threat-hunting",
        "title": "DNS exfiltration -- high subdomain entropy",
        "spl": 'index=* sourcetype=stream:dns query_type=A earliest=-1h | eval subdomain_len=len(query) | where subdomain_len > 50 | stats count, values(query) by src_ip | sort -count',
        "description": "Long DNS queries that may indicate DNS tunneling",
    },
    {
        "category": "vulnerability",
        "title": "Exploitation attempts from CISA KEV IPs",
        "spl": 'index=* [inputlookup kev_cves.csv | rename ip_address as src_ip | table src_ip] earliest=-24h | stats count by src_ip, dest, uri_path | sort -count',
        "description": "Traffic from IPs associated with KEV exploitation",
    },
    {
        "category": "vulnerability",
        "title": "High-risk CVE exploitation keywords",
        "spl": 'index=* ("log4j" OR "spring4shell" OR "proxyshell" OR "zerologon" OR "printnightmare") earliest=-24h | table _time, host, source, _raw',
        "description": "Known exploit technique keywords in raw events",
    },
    {
        "category": "compliance",
        "title": "Admin account activity summary",
        "spl": 'index=* (EventCode=4672 OR "sudo" OR "su -") earliest=-24h | stats count by user, host | sort -count',
        "description": "Privileged account usage over last 24 hours",
    },
    {
        "category": "compliance",
        "title": "Outbound connections to unusual ports",
        "spl": 'index=* sourcetype=firewall action=allowed dest_port NOT IN (80, 443, 22, 25, 53, 8080, 8443) earliest=-4h | stats count by src_ip, dest_ip, dest_port | sort -count',
        "description": "Egress to non-standard ports that may indicate C2",
    },
    {
        "category": "incident-response",
        "title": "All events for a specific host (last 2h)",
        "spl": 'index=* (host="REPLACE_ME" OR dest_host="REPLACE_ME" OR src_ip="REPLACE_ME") earliest=-2h | sort _time | table _time, sourcetype, source, _raw',
        "description": "Replace REPLACE_ME with the hostname or IP under investigation",
    },
]
