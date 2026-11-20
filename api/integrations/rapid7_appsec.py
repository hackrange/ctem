"""Rapid7 InsightAppSec connector -- web application findings."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations import rapid7_common as r7
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-appsec")

_SEVERITY_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFORMATIONAL": 0.0}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
_PAGE = 100


def _status(raw: str | None):
    from api.models.vuln import FindingStatus
    return {
        "FALSE_POSITIVE": FindingStatus.false_positive,
        "REMEDIATED": FindingStatus.remediated,
        "IGNORED": FindingStatus.risk_accepted,
    }.get((raw or "").upper(), FindingStatus.open)


@register(Vendor.rapid7_appsec)
class InsightAppSecConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(f"{self._base}/apps", headers=r7.headers(self.config), params={"size": 1})
            return resp.status_code == 200
        except Exception as e:
            log.warning("InsightAppSec test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        apps = {a["id"]: a.get("name") or a["id"] for a in await self._list_apps()}
        vulns = await self._search_vulns()
        return await self._upsert(apps, vulns, db)

    @property
    def _base(self) -> str:
        return f"{r7.platform_base(self.config)}/ias/v1"

    def _min_severities(self) -> list[str]:
        floor = str(self.config.get("min_severity", "HIGH")).upper()
        if floor not in _SEVERITIES:
            floor = "HIGH"
        return list(_SEVERITIES[: _SEVERITIES.index(floor) + 1])

    async def _list_apps(self) -> list[dict]:
        apps, index = [], 0
        async with safe_client() as client:
            while index < 50:  # 5000 apps is plenty for anyone
                resp = await client.get(f"{self._base}/apps", headers=r7.headers(self.config),
                                        params={"size": _PAGE, "index": index})
                resp.raise_for_status()
                body = resp.json()
                apps.extend(body.get("data", []))
                index += 1
                if index >= body.get("metadata", {}).get("total_pages", 0):
                    break
        return apps

    async def _search_vulns(self) -> list[dict]:
        sev = ",".join(f"'{s}'" for s in self._min_severities())
        query = {"type": "VULNERABILITY", "query": f"vulnerability.severity IN [{sev}]"}
        cap = r7.int_cfg(self.config, "max_findings", 0, 0, 10_000_000)  # 0 = no limit
        out, index = [], 0
        async with safe_client() as client:
            while not cap or len(out) < cap:
                resp = await client.post(f"{self._base}/search", headers=r7.headers(self.config),
                                         params={"size": _PAGE, "index": index}, json=query)
                resp.raise_for_status()
                body = resp.json()
                out.extend(body.get("data", []))
                index += 1
                if index >= body.get("metadata", {}).get("total_pages", 0):
                    break
        return out[:cap] if cap else out

    async def _upsert(self, apps: dict, vulns: list[dict], db: AsyncSession) -> int:
        from sqlalchemy import select

        from api.models.device import Device, DeviceType
        from api.models.vuln import Finding, Vulnerability

        devices: dict[str, Device] = {}
        count = 0
        for v in vulns:
            app_id = (v.get("app") or {}).get("id")
            if not app_id or not v.get("id"):
                continue
            dev = devices.get(app_id)
            if dev is None:
                dev = (await db.execute(select(Device).where(
                    Device.source == "rapid7_appsec", Device.source_id == app_id))).scalar_one_or_none()
                if dev is None:
                    dev = Device(hostname=str(apps.get(app_id, app_id))[:253], device_type=DeviceType.server,
                                 source="rapid7_appsec", source_id=app_id)
                    db.add(dev)
                    await db.flush()
                devices[app_id] = dev

            vuln = (await db.execute(select(Vulnerability).where(
                Vulnerability.source == "rapid7_appsec", Vulnerability.source_vuln_id == v["id"]))).scalar_one_or_none()
            root = v.get("root_cause") or {}
            sev = (v.get("severity") or "MEDIUM").upper()
            if vuln is None:
                vuln = Vulnerability(source="rapid7_appsec", source_vuln_id=v["id"], title="")
                db.add(vuln)
            vuln.title = f"{v.get('attack_type') or 'AppSec finding'} ({root.get('method') or '?'} {root.get('parameter') or ''})".strip()[:512]
            vuln.description = f"{root.get('url') or ''}\n{v.get('insight_ui_url') or ''}".strip()
            vuln.cvss_base = float(v.get("vulnerability_score") or _SEVERITY_CVSS.get(sev, 5.0))
            vuln.cvss_vector = (v.get("vector_string") or "")[:256] or None
            vuln.attack_vector = "network"
            await db.flush()

            finding = (await db.execute(select(Finding).where(
                Finding.device_id == dev.id, Finding.vuln_id == vuln.id))).scalar_one_or_none()
            if finding is None:
                finding = Finding(device_id=dev.id, vuln_id=vuln.id, source="rapid7_appsec", source_id=v["id"])
                db.add(finding)
            finding.status = _status(v.get("status"))
            finding.first_detected = r7.parse_dt(v.get("first_discovered"))
            finding.last_seen = r7.parse_dt(v.get("last_discovered"))
            count += 1
        await db.commit()
        return count
