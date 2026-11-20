"""Rapid7 InsightVM connector -- cloud v4 Integration API or on-prem console v3 API."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations import rapid7_common as r7
from api.integrations.base import BaseConnector, load_sync_state, register, save_sync_state
from api.integrations.rapid7_insightvm_console import ConsoleMixin
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-insightvm")

_SEVERITIES = ("Critical", "Severe", "Moderate")
_ASSET_PAGE = 250
_VULN_BATCH = 100
_OVERLAP = timedelta(hours=1)  # re-ask a little before the bookmark so clock skew can't drop a change


@register(Vendor.rapid7_insightvm)
class InsightVMConnector(ConsoleMixin, BaseConnector):

    @property
    def _cloud(self) -> bool:
        # An Insight Platform key means cloud; username/password means the on-prem console
        mode = self.config.get("mode")
        return mode == "cloud" or (mode != "console" and bool(self.config.get("api_key")))

    @property
    def _v4(self) -> str:
        return f"{r7.platform_base(self.config)}/vm/v4/integration"

    async def test_connection(self) -> bool:
        if not self._cloud:
            return await self._console_test()
        try:
            async with safe_client() as client:
                resp = await client.post(f"{self._v4}/assets", headers=r7.headers(self.config),
                                         params={"size": 1}, json={})
            return resp.status_code == 200
        except Exception as e:
            log.warning("InsightVM test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        if not self._cloud:
            return await self._console_sync(db)
        started = datetime.now(timezone.utc)
        state = await load_sync_state(db, self.integration_id)
        since = self._incremental_since(state, started)
        self.last_mode = "incremental" if since else "full"
        log.info("InsightVM %s sync%s", self.last_mode, f" since {since.isoformat()}" if since else "")
        # Page by page so 10k+ assets and millions of findings never sit in memory at once
        keep = {s.lower() for s in self._severities()}
        fetched: set[str] = set()  # every vuln id already looked up, kept or trimmed
        vuln_ids: dict[str, str] = {}  # rapid7 vuln id -> our Vulnerability.id
        count = 0
        async with safe_client(timeout=120.0) as client:
            async for page in self._cloud_asset_pages(client, since):
                wanted = {f["vulnerability_id"] for a in page for f in a.get("same", []) + a.get("new", [])
                          + a.get("remediated", []) if r7.safe_id(f.get("vulnerability_id", ""))}
                todo = sorted(wanted - fetched - vuln_ids.keys())
                if since is not None:
                    # Incremental: vulns already stored need no API call (the weekly full sync refreshes them)
                    vuln_ids.update(await self._known_vulns(todo, db))
                    todo = [v for v in todo if v not in vuln_ids]
                fetched.update(todo)
                fresh = await self._cloud_vulns(client, todo)
                # The v4 API takes the severity filter but still returns every finding per asset, so trim here
                fresh = {k: v for k, v in fresh.items() if (v.get("severity") or "").lower() in keep}
                await self._upsert_vulns(fresh, vuln_ids, db)
                count += await self._upsert_cloud(page, vuln_ids, db)
                db.expunge_all()  # keep the identity map from growing across pages
        if not self.config.get("max_assets"):  # a capped run is not a complete picture
            await save_sync_state(db, self.integration_id, {
                "last_success": started.isoformat(),
                "last_full": started.isoformat() if since is None else state.get("last_full"),
            })
        return count

    def _incremental_since(self, state: dict, now: datetime) -> datetime | None:
        """Ask only for changes when the last full sync is recent; otherwise do a full sync."""
        if self.config.get("max_assets") or str(self.config.get("full_sync", "")).lower() in ("1", "true", "yes"):
            return None
        last_ok, last_full = r7.parse_dt(state.get("last_success")), r7.parse_dt(state.get("last_full"))
        days = r7.int_cfg(self.config, "full_sync_days", 7, 1, 90)
        if not last_ok or not last_full or now - last_full >= timedelta(days=days):
            return None
        return last_ok - _OVERLAP

    async def _known_vulns(self, ids: list[str], db: AsyncSession) -> dict[str, str]:
        from sqlalchemy import select

        from api.models.vuln import Vulnerability
        out: dict[str, str] = {}
        for i in range(0, len(ids), 500):
            rows = await db.execute(select(Vulnerability.source_vuln_id, Vulnerability.id).where(
                Vulnerability.source == "rapid7_insightvm", Vulnerability.source_vuln_id.in_(ids[i:i + 500])))
            out.update({r[0]: str(r[1]) for r in rows})
        return out

    def _severities(self) -> tuple[str, ...]:
        floor = str(self.config.get("min_severity", "Severe")).capitalize()
        if floor not in _SEVERITIES:
            floor = "Severe"
        return _SEVERITIES[: _SEVERITIES.index(floor) + 1]

    def _severity_filter(self) -> str:
        return "vulnerability.severity IN [" + ",".join(f"'{s}'" for s in self._severities()) + "]"

    async def _cloud_asset_pages(self, client, since: datetime | None = None):
        cap = r7.int_cfg(self.config, "max_assets", 0, 0, 1_000_000)  # 0 = every asset
        body_filter = {"vulnerability": self._severity_filter()}
        params = {"includeSame": "true"}
        if since is not None:
            # Only assets scanned since the bookmark, and only their new + remediated findings
            stamp = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            body_filter["asset"] = f"asset.last_scan_end > {stamp}"
            params = {"includeSame": "false", "comparisonTime": stamp}
        seen, cursor = 0, None
        while not cap or seen < cap:
            page_params = {**params, "size": _ASSET_PAGE if not cap else min(_ASSET_PAGE, cap - seen)}
            if cursor:
                page_params["cursor"] = cursor
            resp = await client.post(f"{self._v4}/assets", headers=r7.headers(self.config),
                                     params=page_params, json=body_filter)
            resp.raise_for_status()
            body = resp.json()
            page = body.get("data", [])
            if page:
                seen += len(page)
                yield page
            cursor = body.get("metadata", {}).get("cursor")
            if not page or not cursor:
                break

    async def _cloud_vulns(self, client, ids: list[str]) -> dict[str, dict]:
        catalog: dict[str, dict] = {}
        for i in range(0, len(ids), _VULN_BATCH):
            chunk = ids[i:i + _VULN_BATCH]
            query = "vulnerability.id IN [" + ",".join(f"'{v}'" for v in chunk) + "]"
            resp = await client.post(f"{self._v4}/vulnerabilities", headers=r7.headers(self.config),
                                     params={"size": len(chunk)}, json={"vulnerability": query})
            resp.raise_for_status()
            for v in resp.json().get("data", []):
                catalog[v["id"]] = v
        return catalog

    async def _upsert_vulns(self, catalog: dict, vuln_ids: dict, db: AsyncSession) -> None:
        from sqlalchemy import select

        from api.models.vuln import Vulnerability

        if not catalog:
            return
        existing = {row.source_vuln_id: row for row in (await db.execute(select(Vulnerability).where(
            Vulnerability.source == "rapid7_insightvm",
            Vulnerability.source_vuln_id.in_(list(catalog))))).scalars()}
        for vid, v in catalog.items():
            vuln = existing.get(vid)
            if vuln is None:
                vuln = Vulnerability(source="rapid7_insightvm", source_vuln_id=vid, title="")
                db.add(vuln)
            cves = [c.strip() for c in (v.get("cves") or "").split(",") if c.strip()]
            vuln.cve_id = cves[0][:32] if cves else None
            vuln.title = (v.get("title") or vid)[:512]
            vuln.description = v.get("description")
            vuln.cvss_base = float(v.get("cvss_v3_score") or v.get("cvss_v2_score") or 0.0)
            vuln.cvss_vector = (v.get("cvss_v3_vector") or v.get("cvss_v2_vector") or "")[:256] or None
            vuln.attack_vector = (v.get("cvss_v3_attack_vector") or "").lower()[:32] or None
            vuln.exploit_available = bool(v.get("exploits"))
        await db.flush()
        for row in (await db.execute(select(Vulnerability.source_vuln_id, Vulnerability.id).where(
                Vulnerability.source == "rapid7_insightvm",
                Vulnerability.source_vuln_id.in_(list(catalog))))).all():
            vuln_ids[row[0]] = str(row[1])
        await db.commit()

    async def _upsert_cloud(self, assets: list[dict], vuln_ids: dict, db: AsyncSession) -> int:
        from sqlalchemy import select

        from api.core.device_match import add_source, find_device, remember_fqdn
        from api.core.encryption import search_hash
        from api.models.device import Device, DeviceType
        from api.models.vuln import Finding, FindingStatus

        count = 0
        for a in assets:
            if not a.get("id"):
                continue
            dev = (await db.execute(select(Device).where(
                Device.source == "rapid7_insightvm", Device.source_id == a["id"]))).scalar_one_or_none()
            hostname = a.get("host_name") or a.get("ip")
            if dev is None and hostname:
                dev = await find_device(db, hostname)
            if dev is None:
                if not hostname:
                    continue
                dev = Device(hostname=hostname[:253], device_type=_device_type(a, DeviceType),
                             source="rapid7_insightvm")
                db.add(dev)
            remember_fqdn(dev, a.get("host_name"))
            add_source(dev, "rapid7_insightvm")
            dev.source_id = dev.source_id or a["id"]
            dev.os = (a.get("os_description") or a.get("os_name") or "")[:128] or dev.os
            dev.os_version = (a.get("os_version") or "")[:128] or dev.os_version
            dev.mac_address = (a.get("mac") or "")[:17] or dev.mac_address
            seen = r7.parse_dt(a.get("last_assessed_for_vulnerabilities") or a.get("last_scan_end"))
            if seen and (dev.last_seen is None or seen > dev.last_seen):
                dev.last_seen = seen
            if a.get("ip"):
                dev.ip, dev.ip_hash = a["ip"], search_hash(a["ip"])
            await db.flush()

            existing = {f.vuln_id: f for f in (await db.execute(select(Finding).where(
                Finding.device_id == dev.id, Finding.source == "rapid7_insightvm"))).scalars()}
            for f in a.get("same", []) + a.get("new", []):
                vuln_id = vuln_ids.get(f.get("vulnerability_id"))
                if vuln_id is None:
                    continue
                finding = existing.get(vuln_id)
                if finding is None:
                    finding = Finding(device_id=dev.id, vuln_id=vuln_id, source="rapid7_insightvm",
                                      source_id=f"{a['id']}:{f['vulnerability_id']}"[:256])
                    db.add(finding)
                    existing[vuln_id] = finding
                if finding.status == FindingStatus.remediated:
                    finding.status = FindingStatus.open  # it came back, sadly
                finding.first_detected = r7.parse_dt(f.get("first_found"))
                finding.last_seen = r7.parse_dt(f.get("last_found"))
                count += 1
            for f in a.get("remediated", []):
                vuln_id = vuln_ids.get(f.get("vulnerability_id"))
                if vuln_id is not None and vuln_id in existing:
                    existing[vuln_id].status = FindingStatus.remediated
            await db.commit()
        return count


def _device_type(asset: dict, DeviceType):
    kind = f"{asset.get('type') or ''} {asset.get('os_type') or ''}".lower()
    if "server" in kind:
        return DeviceType.server
    if "router" in kind or "switch" in kind or "firewall" in kind:
        return DeviceType.network_device
    if "workstation" in kind or "general" in kind:
        return DeviceType.workstation
    return DeviceType.unknown
