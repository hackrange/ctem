"""Palo Alto NGFW connector -- policy and threat log data."""
from __future__ import annotations

import logging
from defusedxml import ElementTree as ET

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.paloalto-ngfw")


@register(Vendor.paloalto_ngfw)
class PaloAltoNGFWConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/api/",
                    params={"type": "version", "key": self.config["api_key"]},
                )
            return resp.status_code == 200 and "<status>success</status>" in resp.text
        except Exception as e:
            log.warning("NGFW test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        """
        Pull address objects, security policies, and recent threat logs.
        These feed into compensating controls -- a device blocked by NGFW policy
        gets reduced reachability.
        """
        blocked_hosts = await self._get_blocked_hosts()
        threat_events = await self._get_threat_logs()
        count = await self._apply_firewall_compensating_controls(blocked_hosts, db)
        await self._cache_threats(threat_events, db)
        return count

    async def _get_blocked_hosts(self) -> list[str]:
        """Return hostnames/IPs explicitly denied in security policies."""
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/",
                params={
                    "type": "config",
                    "action": "get",
                    "xpath": "/config/devices/entry/vsys/entry/security/rules/entry",
                    "key": self.config["api_key"],
                },
            )
        if resp.status_code != 200:
            return []
        return _parse_deny_rules(resp.text)

    async def _get_threat_logs(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/",
                params={
                    "type": "log",
                    "log-type": "threat",
                    "nlogs": "200",
                    "query": "(subtype eq 'vulnerability')",
                    "key": self.config["api_key"],
                },
            )
        if resp.status_code != 200:
            return []
        return _parse_threat_logs(resp.text)

    async def _apply_firewall_compensating_controls(self, blocked: list[str], db: AsyncSession) -> int:
        from api.models.device import Device
        from sqlalchemy import select

        count = 0
        for hostname in blocked:
            result = await db.execute(select(Device).where(Device.hostname == hostname))
            dev = result.scalar_one_or_none()
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
            key = f"threat_alert_ngfw_{ev.get('seqno', '')}"
            payload = {**ev, "source": "paloalto_ngfw"}
            result = await db.execute(select(AppSetting).where(AppSetting.key == key))
            setting = result.scalar_one_or_none() or AppSetting(key=key, is_sensitive=False)
            setting.value = json.dumps(payload)
            db.add(setting)
        await db.commit()

    @property
    def _base(self) -> str:
        return f"https://{self.config['host']}"


def _parse_deny_rules(xml_text: str) -> list[str]:
    """Extract destination addresses from deny rules."""
    blocked = []
    try:
        root = ET.fromstring(xml_text)
        for rule in root.findall(".//entry"):
            action = rule.findtext(".//action")
            if action and action.lower() == "deny":
                for member in rule.findall(".//destination/member"):
                    if member.text:
                        blocked.append(member.text)
    except ET.ParseError:
        pass
    return blocked


def _parse_threat_logs(xml_text: str) -> list[dict]:
    events = []
    try:
        root = ET.fromstring(xml_text)
        for entry in root.findall(".//entry"):
            events.append({
                "seqno": entry.findtext("seqno", ""),
                "severity": entry.findtext("severity", ""),
                "src": entry.findtext("src", ""),
                "dst": entry.findtext("dst", ""),
                "threat_id": entry.findtext("threatid", ""),
                "description": entry.findtext("misc", ""),
            })
    except ET.ParseError:
        pass
    return events
