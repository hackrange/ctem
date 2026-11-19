"""SentinelOne connector -- endpoint inventory and threat data."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.sentinelone")


@register(Vendor.sentinelone)
class SentinelOneConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/web/api/v2.1/system/status",
                    headers=self._headers(),
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("SentinelOne test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        agents = await self._list_agents()
        threats = await self._list_threats()
        count = await self._upsert_agents(agents, db)
        await self._cache_threats(threats, db)
        return count

    async def _list_agents(self) -> list[dict]:
        agents, cursor = [], None
        async with safe_client() as client:
            while True:
                params = {"limit": 1000, "isActive": "true"}
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(
                    f"{self._base}/web/api/v2.1/agents",
                    headers=self._headers(),
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                agents.extend(data.get("data", []))
                cursor = data.get("pagination", {}).get("nextCursor")
                if not cursor:
                    break
        return agents

    async def _list_threats(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/web/api/v2.1/threats",
                headers=self._headers(),
                params={"limit": 500, "resolved": "false"},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("data", [])

    async def _upsert_agents(self, agents: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType
        from api.models.tag import Tag
        from api.models.device import DeviceTag
        from sqlalchemy import select

        # Ensure EDR tag
        result = await db.execute(select(Tag).where(Tag.name == "edr:sentinelone"))
        tag = result.scalar_one_or_none()
        if tag is None:
            tag = Tag(name="edr:sentinelone", source="sentinelone")
            db.add(tag)
            await db.flush()

        count = 0
        for a in agents:
            hostname = a.get("computerName")
            if not hostname:
                continue
            result = await db.execute(select(Device).where(Device.hostname == hostname))
            dev = result.scalar_one_or_none()
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="sentinelone")
                db.add(dev)
                await db.flush()

            dev.os = a.get("osName")
            dev.edr_vendor = "sentinelone"
            dev.edr_active = True
            dev.ad_joined = a.get("domain") is not None

            tag_check = await db.execute(
                select(DeviceTag).where(DeviceTag.device_id == dev.id, DeviceTag.tag_id == tag.id)
            )
            if tag_check.scalar_one_or_none() is None:
                db.add(DeviceTag(device_id=dev.id, tag_id=tag.id))
            count += 1

        await db.commit()
        return count

    async def _cache_threats(self, threats: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json

        for t in threats[:200]:
            key = f"threat_alert_s1_{t.get('id', '')}"
            payload = {
                "source": "sentinelone",
                "id": t.get("id"),
                "severity": t.get("threatInfo", {}).get("confidenceLevel", ""),
                "hostname": t.get("agentRealtimeInfo", {}).get("agentComputerName"),
                "description": t.get("threatInfo", {}).get("threatName"),
                "classification": t.get("threatInfo", {}).get("classification"),
                "mitre_ttps": [a.get("name") for a in t.get("mitigationStatus", [])],
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()

    def _headers(self) -> dict:
        return {"Authorization": f"ApiToken {self.config['api_token']}"}

    @property
    def _base(self) -> str:
        return f"https://{self.config['console_host']}"
