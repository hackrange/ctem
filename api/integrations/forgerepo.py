"""ForgeRepo connector -- SCM repository security findings."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.forgerepo")


@register(Vendor.forgerepo)
class ForgeRepoConnector(BaseConnector):
    """
    ForgeRepo SCM security scanning.
    Pulls secret exposure, dependency vulnerability, and IaC misconfiguration findings.
    """

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/api/v1/version",
                    headers=self._headers(),
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("ForgeRepo test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        findings = await self._list_findings()
        return await self._upsert_findings(findings, db)

    async def _list_findings(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/v1/security/findings",
                headers=self._headers(),
                params={"severity": "critical,high,medium", "state": "open", "limit": 1000},
            )
        resp.raise_for_status()
        return resp.json().get("findings", [])

    async def _upsert_findings(self, findings: list[dict], db: AsyncSession) -> int:
        from api.models.vuln import Vulnerability
        from sqlalchemy import select
        count = 0

        for f in findings:
            cve_id = f.get("cve") or f"forgerepo:{f.get('id', '')}"
            result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
            vuln = result.scalar_one_or_none()
            if vuln is None:
                sev = f.get("severity", "medium")
                db.add(Vulnerability(
                    cve_id=cve_id,
                    cvss_base={"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}.get(sev, 5.0),
                    title=f.get("title", cve_id),
                    description=f.get("description"),
                    source="forgerepo",
                ))
                count += 1

        await db.commit()
        return count

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.config['api_token']}"}

    @property
    def _base(self) -> str:
        return f"https://{self.config['host']}"
