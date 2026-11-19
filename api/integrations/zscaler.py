"""Zscaler ZIA/ZPA connector. Network access data for compensating control scoring."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.zscaler")


@register(Vendor.zscaler)
class ZscalerConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            return bool(token)
        except Exception as e:
            log.warning("Zscaler test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        """
        Pull Zscaler ZIA URL category policies and ZPA application segments.
        Uses this to tag devices as 'network_segmented' which reduces reachability score.
        """
        token = await self._get_token()
        apps = await self._list_zpa_apps(token)
        count = await self._tag_segmented_devices(apps, db)
        return count

    async def _get_token(self) -> str:
        """ZIA uses API key; ZPA uses OAuth2 client credentials."""
        if self.config.get("zpa_client_id"):
            async with safe_client() as client:
                resp = await client.post(
                    f"https://{self.config['cloud']}.zscaler.net/oauth2/token",
                    data={
                        "client_id": self.config["zpa_client_id"],
                        "client_secret": self.config["zpa_client_secret"],
                        "grant_type": "client_credentials",
                    },
                )
            resp.raise_for_status()
            return resp.json()["access_token"]
        # ZIA: return obfuscated API key
        return self.config.get("api_key", "")

    async def _list_zpa_apps(self, token: str) -> list[dict]:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"https://config.{self.config.get('cloud', 'private')}.zscaler.net/mgmtconfig/v1/admin/customers/{self.config.get('customer_id', '')}/application",
                    headers={"Authorization": f"Bearer {token}"},
                )
            resp.raise_for_status()
            return resp.json().get("list", [])
        except Exception:
            return []

    async def _tag_segmented_devices(self, apps: list[dict], db: AsyncSession) -> int:
        """Tag devices that are behind ZPA app segments as network-segmented."""
        from api.models.device import Device
        from api.models.tag import Tag
        from api.models.device import DeviceTag
        from sqlalchemy import select

        # Collect server IPs/FQDNs from ZPA app segments
        protected_hosts: set[str] = set()
        for app in apps:
            for server in app.get("serverGroups", []):
                for s in server.get("servers", []):
                    if s.get("address"):
                        protected_hosts.add(s["address"].lower())

        if not protected_hosts:
            return 0

        # Ensure the tag exists
        result = await db.execute(select(Tag).where(Tag.name == "network:zscaler-zpa"))
        tag = result.scalar_one_or_none()
        if tag is None:
            tag = Tag(name="network:zscaler-zpa", source="zscaler")
            db.add(tag)
            await db.flush()

        count = 0
        for host in protected_hosts:
            result = await db.execute(
                select(Device).where(Device.hostname == host)
            )
            dev = result.scalar_one_or_none()
            if dev:
                # Check tag not already on device
                tag_check = await db.execute(
                    select(DeviceTag).where(DeviceTag.device_id == dev.id, DeviceTag.tag_id == tag.id)
                )
                if tag_check.scalar_one_or_none() is None:
                    db.add(DeviceTag(device_id=dev.id, tag_id=tag.id))
                count += 1

        await db.commit()
        return count
