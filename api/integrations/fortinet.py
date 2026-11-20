"""Fortinet FortiGate connector -- policy and threat log data."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor
from api.core.device_match import find_device

log = logging.getLogger("open-ctem.fortinet")


@register(Vendor.fortinet)
class FortinetConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/api/v2/cmdb/system/status",
                    headers=self._headers(),
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("FortiGate test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        policies = await self._get_policies()
        threat_logs = await self._get_threat_logs()
        count = await self._apply_compensating_controls(policies, db)
        await self._cache_threats(threat_logs, db)
        return count

    async def _get_policies(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/v2/cmdb/firewall/policy",
                headers=self._headers(),
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("results", [])

    async def _get_threat_logs(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/v2/log/disk/ips",
                headers=self._headers(),
                params={"rows": 200, "action": "dropped"},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("results", [])

    async def _apply_compensating_controls(self, policies: list[dict], db: AsyncSession) -> int:
        """Mark devices blocked by deny policies as having compensating control."""

        blocked = set()
        for p in policies:
            if p.get("action") == "deny":
                for addr in p.get("dstaddr", []):
                    name = addr.get("name", "")
                    if name and name not in ("all", "any"):
                        blocked.add(name)

        count = 0
        for hostname in blocked:
            dev = await find_device(db, hostname)
            if dev:
                dev.fw_blocks_inbound = True
                count += 1
        await db.commit()
        return count

    async def _cache_threats(self, events: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json

        for ev in events[:200]:
            key = f"threat_alert_forti_{ev.get('eventtime', '')}"
            payload = {
                "source": "fortinet",
                "severity": ev.get("severity", ""),
                "src": ev.get("srcip"),
                "dst": ev.get("dstip"),
                "attack": ev.get("attack"),
                "description": ev.get("msg"),
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.config['api_key']}",
            "Content-Type": "application/json",
        }

    @property
    def _base(self) -> str:
        return f"https://{self.config['host']}"
