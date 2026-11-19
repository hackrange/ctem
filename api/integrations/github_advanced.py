"""GitHub Advanced Security connector -- code scanning, secret scanning, Dependabot."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.github-advanced-security")

_BASE = "https://api.github.com"


@register(Vendor.github_advanced)
class GitHubAdvancedSecurityConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(f"{_BASE}/user", headers=self._headers())
            return resp.status_code == 200
        except Exception as e:
            log.warning("GitHub Advanced Security test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        org = self.config["org"]
        code_alerts = await self._code_scanning_alerts(org)
        secret_alerts = await self._secret_scanning_alerts(org)
        dep_alerts = await self._dependabot_alerts(org)
        return await self._upsert_all(org, code_alerts, secret_alerts, dep_alerts, db)

    async def _code_scanning_alerts(self, org: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/orgs/{org}/code-scanning/alerts",
                headers=self._headers(),
                params={"state": "open", "severity": "critical,high", "per_page": 100},
            )
        if resp.status_code not in (200, 404):
            resp.raise_for_status()
        return resp.json() if isinstance(resp.json(), list) else []

    async def _secret_scanning_alerts(self, org: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/orgs/{org}/secret-scanning/alerts",
                headers=self._headers(),
                params={"state": "open", "per_page": 100},
            )
        if resp.status_code not in (200, 404):
            resp.raise_for_status()
        return resp.json() if isinstance(resp.json(), list) else []

    async def _dependabot_alerts(self, org: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_BASE}/orgs/{org}/dependabot/alerts",
                headers=self._headers(),
                params={"state": "open", "severity": "critical,high", "per_page": 100},
            )
        if resp.status_code not in (200, 404):
            resp.raise_for_status()
        return resp.json() if isinstance(resp.json(), list) else []

    async def _upsert_all(
        self, org: str, code: list, secrets: list, deps: list, db: AsyncSession
    ) -> int:
        from api.models.vuln import Vulnerability
        from sqlalchemy import select
        count = 0

        for alert in code:
            rule = alert.get("rule", {})
            vuln_id = f"ghas:code:{org}:{rule.get('id', alert.get('number', ''))}"
            result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == vuln_id))
            if result.scalar_one_or_none() is None:
                sev = rule.get("severity", "medium")
                db.add(Vulnerability(
                    cve_id=vuln_id,
                    cvss_base={"critical": 9.5, "high": 7.5, "medium": 5.0, "warning": 3.0, "note": 1.0}.get(sev, 5.0),
                    title=rule.get("description", vuln_id),
                    description=alert.get("most_recent_instance", {}).get("message", {}).get("text"),
                    source="github_advanced",
                ))
                count += 1

        for alert in secrets:
            vuln_id = f"ghas:secret:{org}:{alert.get('number', '')}"
            result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == vuln_id))
            if result.scalar_one_or_none() is None:
                db.add(Vulnerability(
                    cve_id=vuln_id, cvss_base=8.0,
                    title=f"Exposed secret: {alert.get('secret_type_display_name', 'unknown')}",
                    source="github_advanced",
                ))
                count += 1

        for alert in deps:
            cves = alert.get("security_advisory", {}).get("identifiers", [])
            cve_id = next((i["value"] for i in cves if i["type"] == "CVE"), None)
            vuln_id = cve_id or f"ghas:dep:{org}:{alert.get('number', '')}"
            result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == vuln_id))
            if result.scalar_one_or_none() is None:
                cvss = alert.get("security_advisory", {}).get("cvss", {}).get("score", 5.0)
                db.add(Vulnerability(
                    cve_id=vuln_id, cvss_base=float(cvss),
                    title=alert.get("security_advisory", {}).get("summary", vuln_id),
                    source="github_advanced",
                ))
                count += 1

        await db.commit()
        return count

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.config['token']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
