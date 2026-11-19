"""Rapid7 InsightVM connector -- vulnerability findings and asset data."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-insightvm")


@register(Vendor.rapid7_insightvm)
class InsightVMConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/api/3/administration/info",
                    auth=self._auth(),
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("InsightVM test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        assets = await self._list_assets()
        vulns = await self._list_vuln_findings()
        a_count = await self._upsert_assets(assets, db)
        v_count = await self._upsert_findings(vulns, db)
        return a_count + v_count

    async def _list_assets(self) -> list[dict]:
        assets, page = [], 0
        async with safe_client() as client:
            while True:
                resp = await client.get(
                    f"{self._base}/api/3/assets",
                    auth=self._auth(),
                    params={"page": page, "size": 500},
                )
                resp.raise_for_status()
                data = resp.json()
                assets.extend(data.get("resources", []))
                if page >= data.get("page", {}).get("totalPages", 1) - 1:
                    break
                page += 1
                if page > 20:  # safety cap
                    break
        return assets

    async def _list_vuln_findings(self) -> list[dict]:
        """Pull critical/severe findings across all assets."""
        findings, page = [], 0
        async with safe_client() as client:
            while True:
                resp = await client.get(
                    f"{self._base}/api/3/vulnerabilities",
                    auth=self._auth(),
                    params={"page": page, "size": 500},
                )
                resp.raise_for_status()
                data = resp.json()
                findings.extend(data.get("resources", []))
                if page >= data.get("page", {}).get("totalPages", 1) - 1:
                    break
                page += 1
                if page > 20:
                    break
        return findings

    async def _upsert_assets(self, assets: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType
        from sqlalchemy import select

        count = 0
        for a in assets:
            hostname = a.get("hostName") or a.get("ip")
            if not hostname:
                continue
            result = await db.execute(select(Device).where(Device.hostname == hostname))
            dev = result.scalar_one_or_none()
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="rapid7_insightvm")
                db.add(dev)
            dev.os = (a.get("os") or {}).get("name")
            dev.risk_score_raw = float(a.get("riskScore") or 0)
            count += 1
        await db.commit()
        return count

    async def _upsert_findings(self, vulns: list[dict], db: AsyncSession) -> int:
        from api.models.vuln import Vulnerability
        from sqlalchemy import select

        count = 0
        for v in vulns:
            cves = v.get("cves", [])
            if not cves:
                continue
            cve_id = cves[0]
            result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
            vuln = result.scalar_one_or_none()
            if vuln is None:
                cvss = (v.get("cvss") or {}).get("v3", {}).get("score") or \
                       (v.get("cvss") or {}).get("v2", {}).get("score") or 0.0
                vuln = Vulnerability(
                    cve_id=cve_id,
                    cvss_base=float(cvss),
                    title=v.get("title", cve_id),
                    description=v.get("description"),
                    source="rapid7_insightvm",
                )
                db.add(vuln)
                count += 1
        await db.commit()
        return count

    def _auth(self):
        return (self.config["username"], self.config["password"])

    @property
    def _base(self) -> str:
        return f"https://{self.config['host']}:{self.config.get('port', 3780)}"
