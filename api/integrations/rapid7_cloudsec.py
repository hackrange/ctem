"""Rapid7 InsightCloudSec (CSPM) connector -- resources failing Insights, per the public v2 API."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations import rapid7_common as r7
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-cloudsec")

# Insight severity is 1 (Info) to 5 (Critical); map it onto a CVSS-ish number for scoring
_SEVERITY_CVSS = {5: 9.5, 4: 7.5, 3: 5.0, 2: 3.0, 1: 0.0}
_SEVERITY_NAMES = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_PAGE = 1000  # API max per query


@register(Vendor.rapid7_cloudsec)
class InsightCloudSecConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            # No redirects: a bad key or wrong host bounces to the Rapid7 login page with a cheerful 200
            async with safe_client() as client:
                resp = await client.get(f"{self._base}/public/clouds/list", headers=self._headers(),
                                        follow_redirects=False)
            return resp.status_code == 200 and "json" in resp.headers.get("content-type", "")
        except Exception as e:
            log.warning("CloudSec test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        insights = await self._list_insights()
        findings: list[tuple[dict, dict]] = []
        cap = r7.int_cfg(self.config, "max_findings", 0, 0, 10_000_000)  # 0 = no limit
        async with safe_client(timeout=120.0) as client:
            for insight in insights:
                room = (cap - len(findings)) if cap else None
                for res in await self._failing_resources(client, insight, room):
                    findings.append((insight, res))
                if cap and len(findings) >= cap:
                    break
        return await self._upsert(findings, db)

    @property
    def _base(self) -> str:
        # InsightCloudSec lives on a per-tenant host, not the Insight Platform gateway
        base = str(self.config.get("base_url") or "").rstrip("/")
        if base.endswith("/v2"):
            base = base[:-3]
        if not base.startswith("https://"):
            raise ValueError("InsightCloudSec needs base_url like https://us1.cloudsec.insight.rapid7.com")
        return f"{base}/v2"

    def _headers(self) -> dict:
        return {"Api-Key": self.config["api_key"], "Content-Type": "application/json", "Accept": "application/json"}

    def _min_severity(self) -> int:
        raw = str(self.config.get("min_severity", "high")).lower()
        return _SEVERITY_NAMES.get(raw, 4)

    async def _list_insights(self) -> list[dict]:
        async with safe_client(timeout=120.0) as client:
            resp = await client.get(f"{self._base}/public/insights/list", headers=self._headers(),
                                    params={"detail": "true"}, follow_redirects=False)
        resp.raise_for_status()
        body = resp.json()
        rows = body if isinstance(body, list) else body.get("insights", [])
        floor = self._min_severity()
        keep = [i for i in rows if int(i.get("severity") or 0) >= floor and i.get("insight_id") is not None]
        keep.sort(key=lambda i: -int(i.get("severity") or 0))  # worst first, in case the cap bites
        limit = r7.int_cfg(self.config, "max_insights", 0, 0, 100_000)  # 0 = every insight
        return keep[:limit] if limit else keep

    async def _failing_resources(self, client, insight: dict, room: int | None) -> list[dict]:
        """Every resource failing this insight; room caps it, None means no cap."""
        out: list[dict] = []
        source = insight.get("source") or "backoffice"
        for rtype in insight.get("resource_types") or []:
            cursor = None
            while room is None or len(out) < room:
                body = {"selected_resource_type": rtype, "resource_types": [rtype], "scopes": [],
                        "filters": insight.get("filters") or [], "insight": f"{source}:{insight['insight_id']}",
                        "insight_exemptions": False,
                        "limit": _PAGE if room is None else min(_PAGE, room - len(out))}
                if cursor:
                    body["cursor"] = cursor
                resp = await client.post(f"{self._base}/public/resource/query", headers=self._headers(),
                                         json=body, follow_redirects=False)
                if resp.status_code != 200:
                    log.warning("CloudSec query for insight %s/%s returned %s", source, insight["insight_id"], resp.status_code)
                    break
                data = resp.json()
                out.extend(r.get(r.get("resource_type") or rtype) or r for r in data.get("resources", []))
                cursor = data.get("next_cursor")
                if not cursor or not data.get("resources"):
                    break
        return out if room is None else out[:room]

    async def _upsert(self, findings: list[tuple[dict, dict]], db: AsyncSession) -> int:
        from sqlalchemy import select

        from api.models.device import Device, DeviceType
        from api.models.vuln import Finding, FindingStatus, Vulnerability

        vulns: dict[str, Vulnerability] = {}
        devices: dict[str, Device] = {}
        count = 0
        for insight, res in findings:
            common = res.get("common") or res
            rid = common.get("resource_id")
            if not rid:
                continue
            key = f"{insight.get('source') or 'backoffice'}:{insight['insight_id']}"
            vuln = vulns.get(key)
            if vuln is None:
                vuln = (await db.execute(select(Vulnerability).where(
                    Vulnerability.source == "rapid7_cloudsec", Vulnerability.source_vuln_id == key))).scalar_one_or_none()
                if vuln is None:
                    vuln = Vulnerability(source="rapid7_cloudsec", source_vuln_id=key, title="")
                    db.add(vuln)
                sev = int(insight.get("severity") or 3)
                vuln.title = str(insight.get("name") or key)[:512]
                vuln.description = insight.get("description")
                vuln.cvss_base = _SEVERITY_CVSS.get(sev, 5.0)
                await db.flush()
                vulns[key] = vuln

            dev = devices.get(rid)
            if dev is None:
                dev = (await db.execute(select(Device).where(
                    Device.source == "rapid7_cloudsec", Device.source_id == rid[:256]))).scalar_one_or_none()
                if dev is None:
                    name = common.get("resource_name") or common.get("namespace_id") or rid
                    dev = Device(hostname=str(name)[:253], device_type=DeviceType.cloud_instance,
                                 source="rapid7_cloudsec", source_id=rid[:256])
                    db.add(dev)
                    await db.flush()
                devices[rid] = dev

            finding = (await db.execute(select(Finding).where(
                Finding.device_id == dev.id, Finding.vuln_id == vuln.id))).scalar_one_or_none()
            if finding is None:
                finding = Finding(device_id=dev.id, vuln_id=vuln.id, source="rapid7_cloudsec",
                                  source_id=f"{key}:{rid}"[:256], status=FindingStatus.open)
                db.add(finding)
            elif finding.status == FindingStatus.remediated:
                finding.status = FindingStatus.open
            finding.first_detected = finding.first_detected or r7.parse_dt(common.get("discovered_timestamp"))
            finding.last_seen = r7.parse_dt(common.get("modified_timestamp")) or finding.last_seen
            count += 1
        await db.commit()
        return count
