"""InsightVM on-prem Security Console (v3 API, basic auth) half of the connector."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client

log = logging.getLogger("open-ctem.rapid7-insightvm")


class ConsoleMixin:
    config: dict

    @property
    def _console_base(self) -> str:
        return f"https://{self.config['host']}:{int(self.config.get('port', 3780))}"

    def _console_auth(self):
        return (self.config["username"], self.config["password"])

    def _console_client(self):
        # Consoles ship with self-signed certs; opt out of verification only when asked
        return safe_client(verify=not self.config.get("tls_skip_verify"))

    async def _console_test(self) -> bool:
        try:
            async with self._console_client() as client:
                resp = await client.get(f"{self._console_base}/api/3/administration/info", auth=self._console_auth())
            return resp.status_code == 200
        except Exception as e:
            log.warning("InsightVM console test failed: %s", type(e).__name__)
            return False

    async def _console_sync(self, db: AsyncSession) -> int:
        assets = await self._console_pages("/api/3/assets")
        vulns = await self._console_pages("/api/3/vulnerabilities")
        return await self._console_upsert_assets(assets, db) + await self._console_upsert_vulns(vulns, db)

    async def _console_pages(self, path: str) -> list[dict]:
        out, page = [], 0
        async with self._console_client() as client:
            while page <= 20:  # safety cap
                resp = await client.get(f"{self._console_base}{path}", auth=self._console_auth(),
                                        params={"page": page, "size": 500})
                resp.raise_for_status()
                data = resp.json()
                out.extend(data.get("resources", []))
                if page >= data.get("page", {}).get("totalPages", 1) - 1:
                    break
                page += 1
        return out

    async def _console_upsert_assets(self, assets: list[dict], db: AsyncSession) -> int:
        from api.core.device_match import add_source, find_device, remember_fqdn
        from api.core.device_tags import R7_MANAGED, r7_tags, sync_tags
        from api.models.device import Device, DeviceType

        count, tag_cache = 0, {}
        for a in assets:
            hostname = a.get("hostName") or a.get("ip")
            if not hostname:
                continue
            dev = await find_device(db, hostname)
            if dev is None:
                dev = Device(hostname=hostname[:253], device_type=DeviceType.workstation, source="rapid7_insightvm")
                db.add(dev)
            add_source(dev, "rapid7_insightvm")
            remember_fqdn(dev, a.get("hostName"))
            dev.os = ((a.get("os") or "") if isinstance(a.get("os"), str) else (a.get("os") or {}).get("name") or "")[:128] or None
            if a.get("tags") is not None:  # older shippers don't send tags; leave what's there
                names, crit = r7_tags(a["tags"])
                dev.criticality = crit
                await db.flush()
                await sync_tags(db, dev.id, names, R7_MANAGED, "rapid7_insightvm", tag_cache)
            count += 1
        await db.commit()
        return count

    async def _console_upsert_vulns(self, vulns: list[dict], db: AsyncSession) -> int:
        from sqlalchemy import select

        from api.models.vuln import Vulnerability

        count = 0
        for v in vulns:
            cves = v.get("cves", [])
            if not cves:
                continue
            cve_id = cves[0][:32]
            if (await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))).scalars().first():
                continue
            cvss = (v.get("cvss") or {}).get("v3", {}).get("score") or (v.get("cvss") or {}).get("v2", {}).get("score") or 0.0
            db.add(Vulnerability(cve_id=cve_id, cvss_base=float(cvss), title=(v.get("title") or cve_id)[:512],
                                 description=(v.get("description") or {}).get("text") if isinstance(v.get("description"), dict) else v.get("description"),
                                 source="rapid7_insightvm", source_vuln_id=v.get("id")))
            count += 1
        await db.commit()
        return count
