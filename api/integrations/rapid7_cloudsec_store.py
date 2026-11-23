"""Saves InsightCloudSec findings: Insights become vulnerabilities, resources become cloud resources (not hosts),
and a finding on an instance CTEM already has from AWS or OCI lands on that instance."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.integrations import rapid7_common as r7
from api.models.cloud import CloudAsset
from api.models.device import Device, DeviceType
from api.models.integration import IntegrationConfig
from api.models.vuln import Finding, FindingStatus, Vulnerability

SRC = "rapid7_cloudsec"
_OPEN = (FindingStatus.open, FindingStatus.in_progress)
# Insight severity is 1 (Info) to 5 (Critical); map it onto a CVSS-ish number for scoring
_SEVERITY_CVSS = {5: 9.5, 4: 7.5, 3: 5.0, 2: 3.0, 1: 0.0}


def instance_key(row: dict) -> str | None:
    """The provider's own id for an instance ("i-0abc...", "ocid1.instance..."), to find it among CTEM's cloud assets."""
    rid, ns = str(row.get("resource_id") or ""), str(row.get("namespace_id") or "")
    if not rid.startswith("instance:"):
        return None
    if ns.startswith("ocid1.instance."):
        return ns
    if "instance/" in ns:
        return ns.rsplit("instance/", 1)[1] or None
    parts = rid.split(":")
    return parts[3] if len(parts) > 3 and parts[3] else None


def account_of(finding_source_id: str) -> str | None:
    """"backoffice:59:instance:2:us-east-1:i-1:" -> "2", the cloud account the resource lives in."""
    parts = finding_source_id.split(":")
    return parts[3] if len(parts) > 3 and parts[3].isdigit() else None


async def still_enabled(db: AsyncSession, integration_id: str | None) -> bool:
    if not integration_id:
        return True
    return bool((await db.execute(select(IntegrationConfig.is_enabled)
                                  .where(IntegrationConfig.id == integration_id))).scalar_one_or_none())


class Saver:
    """Keeps id maps in memory so a few hundred thousand findings don't cost a query each."""

    def __init__(self, db: AsyncSession, now: datetime) -> None:
        self.db, self.now = db, now
        self.vulns: dict[str, str] = {}
        self.devices: dict[str, str] = {}
        self.findings: dict[str, tuple[str, FindingStatus]] = {}
        self.instances: dict[str, str] = {}   # provider instance id -> the device AWS or OCI made for it
        self.seen: set[str] = set()
        self.refreshed: set[str] = set()
        self.count = 0

    @classmethod
    async def load(cls, db: AsyncSession, now: datetime) -> "Saver":
        s = cls(db, now)
        s.vulns = dict((await db.execute(select(Vulnerability.source_vuln_id, Vulnerability.id)
                                         .where(Vulnerability.source == SRC))).all())
        s.devices = dict((await db.execute(select(Device.source_id, Device.id)
                                           .where(Device.source == SRC))).all())
        s.instances = dict((await db.execute(select(CloudAsset.resource_id, CloudAsset.device_id)
                                             .where(CloudAsset.device_id.is_not(None)))).all())
        s.findings = {sid: (fid, st) for sid, fid, st in (await db.execute(
            select(Finding.source_id, Finding.id, Finding.status).where(Finding.source == SRC))).all()}
        return s

    def _vuln(self, key: str, insight: dict) -> tuple[str, object]:
        sev = int(insight.get("severity") or 3)
        vals = {"title": str(insight.get("name") or key)[:512], "description": insight.get("description"),
                "cvss_base": _SEVERITY_CVSS.get(sev, 5.0)}
        vid = self.vulns.get(key)
        if vid is None:
            vid = str(uuid.uuid4())
            self.db.add(Vulnerability(id=vid, source=SRC, source_vuln_id=key, **vals))
            self.vulns[key] = vid
        elif key not in self.refreshed:   # names and severities change upstream; refresh once a run
            self.refreshed.add(key)
            return vid, update(Vulnerability).where(Vulnerability.id == vid).values(**vals)
        self.refreshed.add(key)
        return vid, None

    def _device(self, rid: str, row: dict) -> str:
        did = self.devices.get(rid)
        if did is None:
            if str(row.get("resource_id") or "").startswith("instance:"):
                did = self.instances.get(str(row.get("namespace_id") or "")) or self.instances.get(instance_key(row) or "")
            if did is None:   # not an instance CTEM knows: its own cloud resource
                did = str(uuid.uuid4())
                name = row.get("resource_name") or row.get("namespace_id") or rid
                self.db.add(Device(id=did, hostname=str(name)[:253], device_type=DeviceType.cloud_resource,
                                   source=SRC, source_id=rid))
            self.devices[rid] = did
        return did

    async def save(self, rows: list[dict], insights: dict) -> None:
        touch, reopen, refresh = [], [], []
        for row in rows:
            key, rid = str(row["insight_id"])[:128], str(row["resource_id"])[:256]
            fsid = f"{key}:{rid}"[:256]
            if fsid in self.seen:
                continue   # the API can list a resource twice under one insight
            self.seen.add(fsid)
            vid, stmt = self._vuln(key, insights[row["insight_id"]])
            if stmt is not None:
                refresh.append(stmt)
            known = self.findings.get(fsid)
            if known is None:
                fid = str(uuid.uuid4())
                self.db.add(Finding(id=fid, device_id=self._device(rid, row), vuln_id=vid, source=SRC,
                                    source_id=fsid, status=FindingStatus.open,
                                    first_detected=r7.parse_dt(row.get("identified_at")), last_seen=self.now))
                self.findings[fsid] = (fid, FindingStatus.open)
            else:
                fid, status = known
                touch.append(fid)
                if status == FindingStatus.remediated:
                    reopen.append(fid)   # it came back, sadly
                    self.findings[fsid] = (fid, FindingStatus.open)
            self.count += 1
        await self.db.flush()
        for stmt in refresh:
            await self.db.execute(stmt)
        for i in range(0, len(touch), 1000):
            await self.db.execute(update(Finding).where(Finding.id.in_(touch[i:i + 1000])).values(last_seen=self.now))
        for i in range(0, len(reopen), 1000):
            await self.db.execute(update(Finding).where(Finding.id.in_(reopen[i:i + 1000]))
                                  .values(status=FindingStatus.open))
        await self.db.commit()

    async def close_missing(self, done: set[str], listed: set[str] | None) -> int:
        """Close open findings the tenant stopped listing: in a fully read account, or one it no longer has."""
        gone = []
        for fsid, (fid, status) in self.findings.items():
            if fsid in self.seen or status not in _OPEN:
                continue
            acct = account_of(fsid)
            if acct in done or (listed is not None and acct is not None and acct not in listed):
                gone.append(fid)
        for i in range(0, len(gone), 1000):
            await self.db.execute(update(Finding).where(Finding.id.in_(gone[i:i + 1000]))
                                  .values(status=FindingStatus.remediated))
        await self.db.commit()
        return len(gone)
