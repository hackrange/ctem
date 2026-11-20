"""Tanium connector. Pulls endpoint inventory, patch status, and threat data."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor
from api.core.device_match import find_device

log = logging.getLogger("open-ctem.tanium")


@register(Vendor.tanium)
class TaniumConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            return bool(token)
        except Exception as e:
            log.warning("Tanium test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        token = await self._get_token()
        endpoints = await self._list_endpoints(token)
        vulns = await self._list_tanium_vulns(token)
        count = await self._upsert(endpoints, vulns, db)
        return count

    async def _get_token(self) -> str:
        async with safe_client() as client:
            resp = await client.post(
                f"{self._base}/api/v2/session/login",
                json={"username": self.config["username"], "password": self.config["password"]},
            )
        resp.raise_for_status()
        return resp.json()["data"]["session"]

    async def _list_endpoints(self, token: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/plugin/products/asset/endpoints",
                headers={"session": token},
                params={"count": 5000},
            )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("endpoints", [])

    async def _list_tanium_vulns(self, token: str) -> list[dict]:
        """Pull findings from Tanium Comply."""
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/plugin/products/comply/api/v1/finding-summaries",
                headers={"session": token},
                params={"count": 5000},
            )
        if resp.status_code == 404:
            return []  # Comply not licensed -- fine
        resp.raise_for_status()
        return resp.json().get("data", [])

    async def _upsert(self, endpoints: list[dict], vulns: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType

        count = 0
        for ep in endpoints:
            name = ep.get("name") or ep.get("computerName")
            if not name:
                continue
            dev = await find_device(db, name)
            if dev is None:
                dev = Device(hostname=name, device_type=DeviceType.workstation, source="tanium")
                db.add(dev)
            dev.os = ep.get("os", {}).get("name")
            dev.os_version = ep.get("os", {}).get("version")
            dev.last_seen = __import__("datetime").datetime.utcnow()
            # Tanium is an EDR alternative
            dev.edr_vendor = dev.edr_vendor or "tanium"
            dev.edr_active = True
            count += 1

        await db.commit()
        return count

    @property
    def _base(self) -> str:
        return f"https://{self.config['host']}"
