"""Qualys VMDR connector -- vulnerability findings and asset data."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from defusedxml import ElementTree as ET

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.qualys")


@register(Vendor.qualys)
class QualysConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/msp/about.php",
                    auth=(self.config["username"], self.config["password"]),
                    headers={"X-Requested-With": "open-ctem"},
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("Qualys test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        hosts = await self._list_hosts()
        vulns = await self._list_vuln_findings()
        host_count = await self._upsert_hosts(hosts, db)
        finding_count = await self._upsert_findings(vulns, db)
        return host_count + finding_count

    async def _list_hosts(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.post(
                f"{self._base}/api/2.0/fo/asset/host/",
                auth=(self.config["username"], self.config["password"]),
                headers={"X-Requested-With": "open-ctem"},
                data={"action": "list", "details": "All", "truncation_limit": 5000},
            )
        resp.raise_for_status()
        return _parse_qualys_hosts(resp.text)

    async def _list_vuln_findings(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.post(
                f"{self._base}/api/2.0/fo/asset/host/vm/detection/",
                auth=(self.config["username"], self.config["password"]),
                headers={"X-Requested-With": "open-ctem"},
                data={
                    "action": "list",
                    "severities": "4,5",  # high and critical
                    "status": "New,Active",
                    "truncation_limit": 10000,
                },
                timeout=120.0,
            )
        resp.raise_for_status()
        return _parse_qualys_detections(resp.text)

    async def _upsert_hosts(self, hosts: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device, DeviceType
        from sqlalchemy import select

        count = 0
        for h in hosts:
            if not h.get("hostname") and not h.get("ip"):
                continue
            hostname = h.get("hostname") or h["ip"]
            result = await db.execute(select(Device).where(Device.hostname == hostname))
            dev = result.scalar_one_or_none()
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="qualys")
                db.add(dev)
            dev.os = h.get("os")
            dev.fqdn = h.get("fqdn")
            count += 1
        await db.commit()
        return count

    async def _upsert_findings(self, detections: list[dict], db: AsyncSession) -> int:
        from api.models.device import Device
        from api.models.vuln import Finding, FindingStatus, Vulnerability
        from sqlalchemy import select

        count = 0
        for d in detections:
            ip = d.get("ip")
            cve_id = d.get("cve_id")
            if not ip or not cve_id:
                continue

            dev_result = await db.execute(select(Device).where(Device.hostname == ip))
            device = dev_result.scalar_one_or_none()
            if device is None:
                continue

            vuln_result = await db.execute(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            )
            vuln = vuln_result.scalar_one_or_none()
            if vuln is None:
                vuln = Vulnerability(
                    cve_id=cve_id,
                    cvss_base=d.get("cvss_base", 0.0),
                    title=d.get("title", cve_id),
                    source="qualys",
                )
                db.add(vuln)
                await db.flush()

            find_result = await db.execute(
                select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.vuln_id == vuln.id,
                )
            )
            finding = find_result.scalar_one_or_none()
            if finding is None:
                finding = Finding(
                    device_id=device.id,
                    vuln_id=vuln.id,
                    status=FindingStatus.open,
                    source="qualys",
                )
                db.add(finding)
            count += 1

        await db.commit()
        return count

    @property
    def _base(self) -> str:
        return f"https://{self.config.get('platform', 'qualysapi.qualys.com')}"


def _parse_qualys_hosts(xml_text: str) -> list[dict]:
    """Parse Qualys host list XML into dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall(".//HOST"):
            hosts.append({
                "ip": _xt(host, "IP"),
                "hostname": _xt(host, "DNS"),
                "fqdn": _xt(host, "DNS"),
                "os": _xt(host, "OS"),
            })
    except ET.ParseError as e:
        log.warning("Qualys XML parse error: %s", e)
    return hosts


def _parse_qualys_detections(xml_text: str) -> list[dict]:
    detections = []
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall(".//HOST"):
            ip = _xt(host, "IP")
            for det in host.findall(".//DETECTION"):
                for cve in det.findall(".//CVE_ID"):
                    detections.append({
                        "ip": ip,
                        "cve_id": cve.text,
                        "cvss_base": float(_xt(det, "CVSS_FINAL") or 0),
                        "title": _xt(det, "TITLE"),
                        "severity": int(_xt(det, "SEVERITY") or 3),
                    })
    except ET.ParseError as e:
        log.warning("Qualys detection XML parse error: %s", e)
    return detections


def _xt(element, tag: str) -> str | None:
    child = element.find(tag)
    return child.text if child is not None else None
