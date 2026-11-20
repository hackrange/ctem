"""Guardicore (Akamai Guardicore Segmentation) connector."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor
from api.core.device_match import add_source, find_device

log = logging.getLogger("open-ctem.guardicore")


@register(Vendor.guardicore)
class GuardicoreConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            return bool(token)
        except Exception as e:
            log.warning("Guardicore test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        token = await self._get_token()
        assets = await self._list_assets(token)
        incidents = await self._list_incidents(token)
        count = await self._upsert(assets, db)
        await self._cache_incidents(incidents, db)
        return count

    async def _get_token(self) -> str:
        async with safe_client() as client:
            resp = await client.post(
                f"{self._base}/api/v3.0/authenticate",
                json={"username": self.config["username"], "password": self.config["password"]},
            )
        resp.raise_for_status()
        return resp.json()["access_token"]

    async def _list_assets(self, token: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/v3.0/assets",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 5000},
            )
        resp.raise_for_status()
        return resp.json().get("objects", [])

    async def _list_incidents(self, token: str) -> list[dict]:
        """Pull recent policy violations and lateral movement incidents."""
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/v3.0/incidents",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 500, "severity": "HIGH,MEDIUM"},
            )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json().get("objects", [])

    async def _upsert(self, assets: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType
        from api.models.tag import Tag
        from api.models.device import DeviceTag
        from sqlalchemy import select

        # Ensure the segmentation tag exists
        result = await db.execute(select(Tag).where(Tag.name == "network:guardicore"))
        tag = result.scalar_one_or_none()
        if tag is None:
            tag = Tag(name="network:guardicore", source="guardicore")
            db.add(tag)
            await db.flush()

        count = 0
        for a in assets:
            name = a.get("name") or a.get("id")
            if not name:
                continue
            dev = await find_device(db, name)
            if dev is None:
                dev = Device(hostname=name, device_type=DeviceType.server, source="guardicore")
                db.add(dev)
                await db.flush()
            add_source(dev, "guardicore")

            # Mark as network-segmented by Guardicore
            tag_check = await db.execute(
                select(DeviceTag).where(DeviceTag.device_id == dev.id, DeviceTag.tag_id == tag.id)
            )
            if tag_check.scalar_one_or_none() is None:
                db.add(DeviceTag(device_id=dev.id, tag_id=tag.id))

            # Guardicore confirms segmentation = compensating control, reduces reachability score
            dev.network_segmented = True
            count += 1

        await db.commit()
        return count

    async def _cache_incidents(self, incidents: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json

        for inc in incidents[:200]:
            key = f"threat_alert_guardicore_{inc.get('id', '')}"
            payload = {
                "source": "guardicore",
                "id": inc.get("id"),
                "severity": inc.get("severity", ""),
                "type": inc.get("incident_type", ""),
                "description": inc.get("description"),
                "source_asset": inc.get("source_asset", {}).get("name"),
                "destination_asset": inc.get("destination_asset", {}).get("name"),
                "affected_assets": [a.get("name") for a in inc.get("affected_assets", [])],
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()

    @property
    def _base(self) -> str:
        return f"https://{self.config['host']}"
