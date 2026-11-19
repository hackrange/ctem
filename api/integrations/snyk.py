"""Snyk connector -- code, container, and dependency vulnerability findings."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.snyk")

_BASE = "https://api.snyk.io/rest"
_VERSION = "2024-01-04"


@register(Vendor.snyk)
class SnykConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{_BASE}/orgs",
                    headers=self._headers(),
                    params={"version": _VERSION, "limit": 1},
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("Snyk test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        orgs = await self._list_orgs()
        total = 0
        for org in orgs[:5]:  # cap to avoid token explosion
            issues = await self._list_issues(org["id"])
            total += await self._upsert_issues(org, issues, db)
        return total

    async def _list_orgs(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/orgs",
                headers=self._headers(),
                params={"version": _VERSION, "limit": 10},
            )
        resp.raise_for_status()
        return resp.json().get("data", [])

    async def _list_issues(self, org_id: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/orgs/{org_id}/issues",
                headers=self._headers(),
                params={
                    "version": _VERSION,
                    "limit": 1000,
                    "severity": "critical,high",
                    "type": "package_vulnerability,code_vulnerability,license",
                },
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("data", [])

    async def _upsert_issues(self, org: dict, issues: list[dict], db: AsyncSession) -> int:
        from api.models.vuln import Vulnerability
        from sqlalchemy import select

        count = 0
        for issue in issues:
            attrs = issue.get("attributes", {})
            problems = attrs.get("problems", [])
            cve_id = None
            for p in problems:
                if p.get("source") == "CVE":
                    cve_id = p.get("id")
                    break
            if not cve_id:
                cve_id = f"snyk:{issue.get('id', '')}"

            result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
            vuln = result.scalar_one_or_none()
            if vuln is None:
                sev = attrs.get("effective_severity_level", "medium")
                cvss = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}.get(sev, 5.0)
                vuln = Vulnerability(
                    cve_id=cve_id,
                    cvss_base=cvss,
                    title=attrs.get("title", cve_id),
                    description=attrs.get("description"),
                    source="snyk",
                )
                db.add(vuln)
                count += 1

        await db.commit()
        return count

    def _headers(self) -> dict:
        return {
            "Authorization": f"token {self.config['api_token']}",
            "Content-Type": "application/vnd.api+json",
        }
