"""SentinelOne connector -- endpoint inventory and threat data."""
from __future__ import annotations

import logging
import re

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor
from api.core.device_match import add_source, find_device

log = logging.getLogger("open-ctem.sentinelone")


_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def agent_id(a: dict) -> str | None:
    """SentinelOne's own id for the agent (stable across renames)."""
    v = str(a.get("uuid") or a.get("id") or "")
    return v if _ID.match(v) else None


def may_claim(dev, aid: str | None, active: set[str]) -> bool:
    """A device found by name may take this agent unless another SentinelOne agent that is still active holds it
    (two live agents with one name: a rogue or cloned host). An old agent gone from the list was a reimage."""
    held = dev.edr_device_id if dev.edr_vendor == "sentinelone" else None
    return not held or held == aid or held not in active


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
        active = {i for i in (agent_id(a) for a in agents) if i}
        by_id = {d.edr_device_id: d for d in (await db.execute(select(Device).where(
            Device.edr_vendor == "sentinelone", Device.edr_device_id.is_not(None)))).scalars()}
        for a in agents:
            hostname = a.get("computerName")
            aid = agent_id(a)
            if not hostname:
                continue
            # The agent's own id first: a renamed host stays itself, and a name alone can't move it
            dev = by_id.get(aid) if aid else None
            if dev is None:
                dev = await find_device(db, hostname)
                if dev is not None and not may_claim(dev, aid, active):
                    log.info("SentinelOne: an agent's name matches a device another active agent holds; skipped")
                    continue
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="sentinelone")
                db.add(dev)
                await db.flush()
            add_source(dev, "sentinelone")

            if dev.edr_vendor in (None, "", "none", "sentinelone") or not dev.edr_device_id:
                # another EDR's identity on this host (its vendor and host id) is never overwritten
                dev.os = a.get("osName")
                dev.edr_vendor = "sentinelone"
                dev.edr_active = True
                if aid:
                    dev.edr_device_id = aid
                    by_id[aid] = dev
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
