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
# Isolated from the network until someone lifts it; pending only means it hasn't taken yet
_CONTAINED = {"contained", "lift_containment_pending"}


def detected_owner(people, last: str | None, history: list[str]) -> str | None:
    """Last sign-in if it's a person; else the newest real account in the login history; aliases last."""
    alias = None
    for name in [last, *history]:
        uid, via_alias = people.resolve(name)
        if uid and not via_alias:
            return uid
        alias = alias or uid
    return alias


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
        from api.core.device_match import add_source, find_device, type_from_os
        from api.core.encryption import search_hash
        from sqlalchemy import inspect as sa_inspect

        from api.core.user_match import UserIndex, bare
        from api.models.device import Device, DeviceType

        people = await UserIndex.load(db)
        count = 0
        for d in devices:
            hostname = d.get("hostname") or d.get("device_id")
            if not hostname:
                continue
            dev = await find_device(db, hostname)
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="crowdstrike")
                db.add(dev)
            add_source(dev, "crowdstrike")
            dev.edr_vendor = "crowdstrike"
            dev.edr_active = d.get("status") in _SENSOR_RUNNING
            if d.get("status"):
                dev.edr_contained = d["status"] in _CONTAINED
            dev.os = d.get("os_version")
            kind = (d.get("product_type") or d.get("product_type_desc") or "").lower()
            if kind in ("server", "domain controller"):
                dev.device_type = DeviceType.server
            elif kind == "workstation" and dev.device_type in (DeviceType.unknown, None):
                dev.device_type = DeviceType.workstation
            dev.device_type = type_from_os(dev.os, dev.device_type)
            for f in ("firewall_enabled", "usb_storage_blocked"):
                if isinstance(d.get(f), bool):
                    setattr(dev, f, d[f])
            user = (d.get("last_login_user") or "").strip()
            if any(ord(ch) < 32 for ch in user):
                user = ""
            if user:
                dev.last_login_user = user[:256]
                dev.last_login_user_hash = search_hash(bare(user))
            history = [n for n in (d.get("recent_logins") or []) if isinstance(n, str)][:20]
            if history:
                dev.recent_logins = history
            history = history or dev.recent_logins or []
            if user or history:
                # Detected user; a person's assignment lives in device_assignments and wins over this
                owner = detected_owner(people, user, history)
                if owner != dev.owner_user_id:
                    dev.owner_user_id = owner
                    if dev.id and "owner" not in sa_inspect(dev).unloaded:
                        db.expire(dev, ["owner"])  # don't serve the previous person from the session cache
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
