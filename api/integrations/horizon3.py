"""Horizon3 NodeZero connector -- pentest reachability validation."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor
from api.core.device_match import find_device

log = logging.getLogger("open-ctem.horizon3")

_API_BASE = "https://api.horizon3.ai/v1"


@register(Vendor.horizon3)
class Horizon3Connector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{_API_BASE}/pentest/ops",
                    headers=self._headers(),
                    params={"limit": 1},
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("Horizon3 test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        ops = await self._list_ops()
        count = 0
        for op in ops[:20]:  # process last 20 ops
            findings = await self._get_op_findings(op["op_id"])
            count += await self._upsert_findings(findings, db)
        return count

    async def _list_ops(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_API_BASE}/pentest/ops",
                headers=self._headers(),
                params={"limit": 20, "sort": "-created_at"},
            )
        resp.raise_for_status()
        return resp.json().get("ops", [])

    async def _get_op_findings(self, op_id: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_API_BASE}/pentest/ops/{op_id}/weaknesses",
                headers=self._headers(),
                params={"limit": 1000},
            )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json().get("weaknesses", [])

    async def _upsert_findings(self, findings: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device
        from api.models.vuln import Finding, Vulnerability
        from sqlalchemy import select

        count = 0
        for f in findings:
            affected_host = f.get("affected_host") or f.get("ip_address")
            if not affected_host:
                continue

            # Find the device
            device = await find_device(db, affected_host)
            if device is None:
                continue  # only update known devices, don't create phantom ones

            cve_id = f.get("cve_ids", [None])[0]
            is_exploitable = f.get("exploited", False)

            # Find matching finding by CVE
            if cve_id:
                vuln_result = await db.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == cve_id)
                )
                vuln = vuln_result.scalar_one_or_none()
                if vuln:
                    finding_result = await db.execute(
                        select(Finding).where(
                            Finding.device_id == device.id,
                            Finding.vuln_id == vuln.id,
                        )
                    )
                    finding = finding_result.scalar_one_or_none()
                    if finding:
                        # NodeZero is the authority on reachability
                        finding.is_reachable = is_exploitable
                        finding.reachability_source = "horizon3"
                        finding.reachability_updated_at = datetime.now(timezone.utc)
                        count += 1

        await db.commit()
        return count

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.config['api_key']}",
            "Content-Type": "application/json",
        }
