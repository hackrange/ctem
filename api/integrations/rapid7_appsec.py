"""Rapid7 InsightAppSec connector -- web application findings."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-appsec")

_BASE = "https://us.api.insight.rapid7.com/ias/v1"


@register(Vendor.rapid7_appsec)
class InsightAppSecConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(f"{_BASE}/apps", headers=self._headers(), params={"size": 1})
            return resp.status_code == 200
        except Exception as e:
            log.warning("InsightAppSec test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        apps = await self._list_apps()
        total = 0
        for app in apps:
            vulns = await self._list_app_vulns(app["id"])
            total += await self._upsert_vulns(app, vulns, db)
        return total

    async def _list_apps(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(f"{_BASE}/apps", headers=self._headers(), params={"size": 100})
        resp.raise_for_status()
        return resp.json().get("data", [])

    async def _list_app_vulns(self, app_id: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/vulnerabilities",
                headers=self._headers(),
                params={"app-id": app_id, "size": 1000, "severity": "HIGH,CRITICAL"},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("data", [])

    async def _upsert_vulns(self, app: dict, vulns: list[dict], db: AsyncSession) -> int:
        from api.models.vuln import Vulnerability
        from sqlalchemy import select

        count = 0
        for v in vulns:
            # AppSec uses internal IDs, not CVEs -- store as app:finding_id
            vuln_id = f"appsec:{app['id']}:{v['id']}"
            result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == vuln_id))
            vuln = result.scalar_one_or_none()
            if vuln is None:
                severity = v.get("severity", "MEDIUM")
                cvss = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(severity, 5.0)
                vuln = Vulnerability(
                    cve_id=vuln_id,
                    cvss_base=cvss,
                    title=v.get("rootCause", {}).get("url", v.get("variantHints", [{}])[0].get("name", vuln_id)),
                    description=f"{app.get('name', 'Unknown App')}: {v.get('description', '')}",
                    source="rapid7_appsec",
                )
                db.add(vuln)
                count += 1
        await db.commit()
        return count

    def _headers(self) -> dict:
        return {"X-Api-Key": self.config["api_key"], "Content-Type": "application/json"}
