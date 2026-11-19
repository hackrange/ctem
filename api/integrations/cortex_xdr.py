"""Palo Alto Cortex XDR connector -- incidents and endpoint inventory."""
from __future__ import annotations

import hashlib
import logging
import string
import time

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.cortex-xdr")


@register(Vendor.cortex_xdr)
class CortexXDRConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.post(
                    f"{self._base}/public_api/v1/endpoints/get_endpoint/",
                    headers=self._headers(),
                    json={"request_data": {"filters": [], "search_from": 0, "search_to": 1}},
                )
            return resp.status_code in (200, 401)  # 401 = reachable, auth issue
        except Exception as e:
            log.warning("Cortex XDR test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        endpoints = await self._list_endpoints()
        incidents = await self._list_incidents()
        count = await self._upsert_endpoints(endpoints, db)
        await self._cache_incidents(incidents, db)
        return count

    async def _list_endpoints(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.post(
                f"{self._base}/public_api/v1/endpoints/get_endpoint/",
                headers=self._headers(),
                json={"request_data": {"search_from": 0, "search_to": 2000}},
            )
        resp.raise_for_status()
        return resp.json().get("reply", {}).get("endpoints", [])

    async def _list_incidents(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.post(
                f"{self._base}/public_api/v1/incidents/get_incidents/",
                headers=self._headers(),
                json={
                    "request_data": {
                        "filters": [{"field": "status", "operator": "in", "value": ["new", "under_investigation"]}],
                        "search_from": 0,
                        "search_to": 500,
                    }
                },
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("reply", {}).get("incidents", [])

    async def _upsert_endpoints(self, endpoints: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType
        from api.models.tag import Tag
        from api.models.device import DeviceTag
        from sqlalchemy import select

        result = await db.execute(select(Tag).where(Tag.name == "edr:cortex-xdr"))
        tag = result.scalar_one_or_none()
        if tag is None:
            tag = Tag(name="edr:cortex-xdr", source="cortex_xdr")
            db.add(tag)
            await db.flush()

        count = 0
        for ep in endpoints:
            hostname = ep.get("host_name") or ep.get("endpoint_name")
            if not hostname:
                continue
            result = await db.execute(select(Device).where(Device.hostname == hostname))
            dev = result.scalar_one_or_none()
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="cortex_xdr")
                db.add(dev)
                await db.flush()

            dev.os = ep.get("os_type")
            dev.edr_vendor = "cortex_xdr"
            dev.edr_active = ep.get("endpoint_status") == "CONNECTED"

            tag_check = await db.execute(
                select(DeviceTag).where(DeviceTag.device_id == dev.id, DeviceTag.tag_id == tag.id)
            )
            if tag_check.scalar_one_or_none() is None:
                db.add(DeviceTag(device_id=dev.id, tag_id=tag.id))
            count += 1

        await db.commit()
        return count

    async def _cache_incidents(self, incidents: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json

        for inc in incidents[:200]:
            key = f"threat_alert_xdr_{inc.get('incident_id', '')}"
            payload = {
                "source": "cortex_xdr",
                "id": inc.get("incident_id"),
                "severity": inc.get("severity", ""),
                "description": inc.get("description"),
                "hosts": inc.get("hosts", []),
                "alert_count": inc.get("alert_count", 0),
                "mitre_ttps": inc.get("mitre_tactics_ids", []),
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()

    def _headers(self) -> dict:
        """Cortex XDR uses an HMAC-based auth scheme."""
        api_key = self.config["api_key"]
        api_key_id = self.config["api_key_id"]
        nonce = "".join([secrets_choice() for _ in range(64)])
        timestamp = int(time.time() * 1000)
        auth_string = f"{api_key}{nonce}{timestamp}"
        auth_hash = hashlib.sha256(auth_string.encode()).hexdigest()
        return {
            "x-xdr-auth-id": str(api_key_id),
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-auth-hash": auth_hash,
            "Content-Type": "application/json",
        }

    @property
    def _base(self) -> str:
        return f"https://api-{self.config['fqdn']}"


def secrets_choice() -> str:
    import secrets
    return secrets.choice(string.ascii_letters + string.digits)
