"""CrowdStrike Falcon connector. Syncs devices + threat detections."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.crowdstrike")

_API_BASE = "https://api.crowdstrike.com"
# Contained hosts still have a working sensor; it just isolates them
_SENSOR_RUNNING = {"normal", "containment_pending", "contained", "lift_containment_pending"}


@register(Vendor.crowdstrike)
class CrowdStrikeConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            return bool(token)
        except Exception as e:
            log.warning("CrowdStrike test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        token = await self._get_token()
        devices = await self._list_devices(token)
        detections = await self._list_detections(token)
        count = await self._upsert(devices, detections, db)
        await self._cache_threats(detections, db)
        return count

    async def _get_token(self) -> str:
        async with safe_client() as client:
            resp = await client.post(
                f"{_API_BASE}/oauth2/token",
                data={
                    "client_id": self.config["client_id"],
                    "client_secret": self.config["client_secret"],
                },
            )
        resp.raise_for_status()
        return resp.json()["access_token"]

    async def _list_devices(self, token: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_API_BASE}/devices/queries/devices/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 5000},
            )
            resp.raise_for_status()
            ids = resp.json().get("resources", [])
            if not ids:
                return []
            detail = await client.post(
                f"{_API_BASE}/devices/entities/devices/v2",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": ids[:500]},
            )
        return detail.json().get("resources", [])

    async def _list_detections(self, token: str) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{_API_BASE}/detects/queries/detects/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 1000, "filter": "status:'new'"},
            )
            resp.raise_for_status()
            ids = resp.json().get("resources", [])
            if not ids:
                return []
            detail = await client.post(
                f"{_API_BASE}/detects/entities/summaries/GET/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": ids[:500]},
            )
        return detail.json().get("resources", [])

    async def _upsert(self, devices: list[dict], detections: list[dict], db: AsyncSession) -> int:
        from api.core.device_match import find_device
        from api.core.encryption import search_hash
        from api.models.device import Device, DeviceType

        count = 0
        for d in devices:
            hostname = d.get("hostname") or d.get("device_id")
            if not hostname:
                continue
            dev = await find_device(db, hostname)
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="crowdstrike")
                db.add(dev)
            dev.edr_vendor = "crowdstrike"
            dev.edr_active = d.get("status") in _SENSOR_RUNNING
            dev.os = d.get("os_version")
            user = (d.get("last_login_user") or "").strip()
            if user and not any(ord(ch) < 32 for ch in user):
                dev.last_login_user = user[:256]
                dev.last_login_user_hash = search_hash(user.split("\\")[-1])
            dev.edr_last_seen = __import__("datetime").datetime.utcnow()
            count += 1

        await db.commit()
        return count

    async def _cache_threats(self, detections: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json
        for det in detections[:200]:
            key = f"threat_alert_{det.get('detection_id', '')}"
            payload = {
                "source": "crowdstrike",
                "id": det.get("detection_id"),
                "severity": det.get("max_severity_displayname", ""),
                "tactic": det.get("tactic", ""),
                "technique": det.get("technique", ""),
                "hostname": det.get("device", {}).get("hostname"),
                "description": det.get("behaviors", [{}])[0].get("description") if det.get("behaviors") else None,
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()
