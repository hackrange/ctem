"""Microsoft Defender for Endpoint connector."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.msdefender")

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"  # nosec B105 - an endpoint, not a secret
_API_BASE = "https://api.securitycenter.microsoft.com/api"


@register(Vendor.msdefender)
class MSDefenderConnector(BaseConnector):

    _token: str | None = None
    _token_expires: datetime | None = None

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            return bool(token)
        except Exception as e:
            log.warning("MS Defender test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        machines = await self._list_machines()
        alerts = await self._list_alerts()
        count = await self._upsert_machines(machines, db)
        await self._cache_alerts(alerts, db)
        return count

    async def _get_token(self) -> str:
        if self._token and self._token_expires and self._token_expires > datetime.now(timezone.utc):
            return self._token
        async with safe_client() as client:
            resp = await client.post(
                _TOKEN_URL.format(tenant_id=self.config["tenant_id"]),
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config["client_id"],
                    "client_secret": self.config["client_secret"],
                    "scope": "https://api.securitycenter.microsoft.com/.default",
                },
            )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        from datetime import timedelta
        self._token_expires = datetime.now(timezone.utc) + timedelta(seconds=data.get("expires_in", 3600) - 60)
        return self._token

    async def _list_machines(self) -> list[dict]:
        token = await self._get_token()
        async with safe_client() as client:
            resp = await client.get(
                f"{_API_BASE}/machines",
                headers={"Authorization": f"Bearer {token}"},
                params={"$top": 1000},
            )
        resp.raise_for_status()
        return resp.json().get("value", [])

    async def _list_alerts(self) -> list[dict]:
        token = await self._get_token()
        async with safe_client() as client:
            resp = await client.get(
                f"{_API_BASE}/alerts",
                headers={"Authorization": f"Bearer {token}"},
                params={"$filter": "status ne 'Resolved'", "$top": 500},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("value", [])

    async def _upsert_machines(self, machines: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType
        from api.models.tag import Tag
        from api.models.device import DeviceTag
        from sqlalchemy import select

        result = await db.execute(select(Tag).where(Tag.name == "edr:msdefender"))
        tag = result.scalar_one_or_none()
        if tag is None:
            tag = Tag(name="edr:msdefender", source="msdefender")
            db.add(tag)
            await db.flush()

        count = 0
        for m in machines:
            hostname = m.get("computerDnsName") or m.get("id")
            if not hostname:
                continue
            result = await db.execute(select(Device).where(Device.hostname == hostname))
            dev = result.scalar_one_or_none()
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="msdefender")
                db.add(dev)
                await db.flush()

            dev.os = m.get("osPlatform")
            dev.edr_vendor = "msdefender"
            dev.edr_active = m.get("healthStatus") == "Active"
            dev.risk_score_raw = {"high": 80, "medium": 50, "low": 20, "informational": 10, "none": 0}.get(
                m.get("riskScore", "none").lower(), 0
            )

            tag_check = await db.execute(
                select(DeviceTag).where(DeviceTag.device_id == dev.id, DeviceTag.tag_id == tag.id)
            )
            if tag_check.scalar_one_or_none() is None:
                db.add(DeviceTag(device_id=dev.id, tag_id=tag.id))
            count += 1

        await db.commit()
        return count

    async def _cache_alerts(self, alerts: list[dict], db: AsyncSession) -> None:
        from api.models.settings import AppSetting
        from sqlalchemy import select
        import json

        for a in alerts[:200]:
            key = f"threat_alert_mde_{a.get('id', '')}"
            payload = {
                "source": "msdefender",
                "id": a.get("id"),
                "severity": a.get("severity", ""),
                "hostname": a.get("computerDnsName"),
                "description": a.get("title"),
                "category": a.get("category"),
                "mitre_technique": a.get("mitreTechniques", []),
            }
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()
