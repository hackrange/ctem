"""Rapid7 InsightCloudSec (DivvyCloud) connector -- cloud posture findings."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-cloudsec")

_BASE = "https://us.api.insight.rapid7.com/cloudsecc/v2"


@register(Vendor.rapid7_cloudsec)
class InsightCloudSecConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{_BASE}/issues/list",
                    headers=self._headers(),
                    params={"limit": 1},
                )
            return resp.status_code in (200, 400)  # 400 means auth OK, bad params
        except Exception as e:
            log.warning("CloudSec test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        issues = await self._list_issues()
        return await self._upsert_issues(issues, db)

    async def _list_issues(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.post(
                f"{_BASE}/issues/list",
                headers=self._headers(),
                json={"limit": 500, "severities": ["CRITICAL", "HIGH", "MEDIUM"]},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("issues", [])

    async def _upsert_issues(self, issues: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType
        from api.models.vuln import Finding, FindingStatus, Vulnerability
        from sqlalchemy import select

        count = 0
        for issue in issues:
            resource_id = issue.get("resource_id", "")
            resource_name = issue.get("resource_name") or resource_id or "unknown-cloud"

            dev_result = await db.execute(select(Device).where(Device.hostname == resource_name))
            dev = dev_result.scalar_one_or_none()
            if dev is None:
                dev = Device(hostname=resource_name, device_type=DeviceType.cloud, source="rapid7_cloudsec")
                dev.cloud_provider = issue.get("cloud_type_id", "").lower()
                db.add(dev)
                await db.flush()

            vuln_key = f"cloudsec:{issue.get('type_id', '')}:{issue.get('id', '')}"
            vuln_result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == vuln_key))
            vuln = vuln_result.scalar_one_or_none()
            if vuln is None:
                sev = issue.get("severity", "MEDIUM")
                cvss = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(sev, 5.0)
                vuln = Vulnerability(
                    cve_id=vuln_key,
                    cvss_base=cvss,
                    title=issue.get("title", vuln_key),
                    description=issue.get("description"),
                    source="rapid7_cloudsec",
                )
                db.add(vuln)
                await db.flush()

            find_result = await db.execute(
                select(Finding).where(Finding.device_id == dev.id, Finding.vuln_id == vuln.id)
            )
            if find_result.scalar_one_or_none() is None:
                db.add(Finding(device_id=dev.id, vuln_id=vuln.id, status=FindingStatus.open, source="rapid7_cloudsec"))
                count += 1

        await db.commit()
        return count

    def _headers(self) -> dict:
        return {"X-Api-Key": self.config["api_key"], "Content-Type": "application/json"}
