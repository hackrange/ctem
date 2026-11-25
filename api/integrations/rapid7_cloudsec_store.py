"""Saves InsightCloudSec findings: Insights become vulnerabilities, resources become cloud resources (not hosts),
and a finding on an instance CTEM already has from AWS or OCI lands on that instance."""
from __future__ import annotations

import re
import uuid
from datetime import datetime

from sqlalchemy import bindparam, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.core import fixes
from api.integrations import rapid7_common as r7
from api.scoring import cloud_score
from api.models.cloud import CloudAsset
from api.models.device import Device, DeviceType
from api.models.integration import IntegrationConfig, Vendor
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


_LINK = re.compile(r"https://[^\s)\]>\"']{4,400}")
_PROVIDER = {"AWS": "AWS", "AWS_GOV": "AWS", "AWS_CHINA": "AWS", "AZURE_ARM": "Azure", "AZURE_GOV": "Azure", "AZURE_CHINA": "Azure",
             "GCE": "Google Cloud", "OCI": "OCI", "ALICLOUD": "Alibaba Cloud", "K8S": "Kubernetes"}


def _clean(v, n: int) -> str | None:
    t = re.sub(r"[\x00-\x08\x0b-\x1f]", "", str(v or "")).strip()
    return t[:n] or None


def details_for(row: dict, insight: dict, accounts: dict[str, dict]) -> dict:
    """Where the finding is (provider, account, region, resource type and id, ARN) and what the check is about."""
    parts = str(row.get("resource_id") or "").split(":")   # "instance:1:us-east-1:i-09208...:"
    acct = accounts.get(parts[1] if len(parts) > 1 else "") or {}
    tags = [t for t in (_clean(x, 60) for x in (insight.get("tags") or [])[:12]) if t]
    controls = []
    for c in (insight.get("compliance_controls") or [])[:20]:
        name = _clean(c.get("name") or c.get("control_name") or c.get("id") if isinstance(c, dict) else c, 120)
        if name and name not in controls:
            controls.append(name)
    out = {"provider": acct.get("provider"), "account": acct.get("name"), "account_id": acct.get("account_id"),
           "region": _clean(parts[2] if len(parts) > 2 else None, 64), "resource_type": _clean(parts[0], 64),
           "resource": _clean(parts[3] if len(parts) > 3 else None, 300), "arn": _clean(row.get("namespace_id"), 500),
           "severity": int(insight.get("severity") or 3), "signals": cloud_score.signals(insight.get("name"), tags),
           "tags": tags[:8], "compliance": controls[:10]}
    return {k: v for k, v in out.items() if v not in (None, [], "")}


def fix_for(key: str, insight: dict) -> tuple[str | None, dict | None]:
    """One fix per check: Rapid7's own write-up (overview and remediation), as plain text with its https links."""
    fk = fixes.key(SRC, key)
    notes = str(insight.get("notes") or "")
    if not fk:
        return None, None
    text = re.sub(r"^\s*[-=]{3,}\s*$", "", notes, flags=re.M)              # markdown heading underlines
    text = re.sub(r"\n{3,}", "\n\n", re.sub(r"<[^>]*>", " ", text)).strip()  # never markup
    links = list(dict.fromkeys(u.rstrip(".,;:") for u in _LINK.findall(notes)))[:10]   # not the sentence's full stop
    return fk, {"source": SRC, "title": f"Fix: {str(insight.get('name') or key)}"[:512], "kind": "configuration",
                "steps": text[:4000] or _clean(insight.get("description"), 1000), "links": links}


def account_of(finding_source_id: str) -> str | None:
    """"backoffice:59:instance:2:us-east-1:i-1:" -> "2", the cloud account the resource lives in."""
    parts = finding_source_id.split(":")
    return parts[3] if len(parts) > 3 and parts[3].isdigit() else None


async def still_enabled(db: AsyncSession, integration_id: str | None) -> bool:
    if not integration_id:
        return True
    return bool((await db.execute(select(IntegrationConfig.is_enabled)
                                  .where(IntegrationConfig.id == integration_id))).scalar_one_or_none())


async def others_enabled(db: AsyncSession, integration_id: str | None) -> bool:
    """Another enabled InsightCloudSec integration shares the findings table (their tool account numbers overlap)."""
    if not integration_id:
        return False
    return (await db.execute(select(IntegrationConfig.id).where(
        IntegrationConfig.vendor == Vendor.rapid7_cloudsec, IntegrationConfig.is_enabled == True,  # noqa: E712
        IntegrationConfig.id != integration_id).limit(1))).first() is not None


class Saver:
    """Keeps id maps in memory so a few hundred thousand findings don't cost a query each."""

    def __init__(self, db: AsyncSession, now: datetime, integration_id: str | None = None) -> None:
        self.db, self.now, self.integration_id = db, now, (str(integration_id) if integration_id else None)
        self.owner: dict[str, str | None] = {}   # finding -> the integration that reported it
        self.vulns: dict[str, str] = {}
        self.devices: dict[str, str] = {}
        self.findings: dict[str, tuple[str, FindingStatus]] = {}
        self.context: dict[str, tuple[dict | None, str | None]] = {}   # finding -> (details, fix_key) as stored
        self.accounts: dict[str, dict] = {}   # the tool's account id -> name, provider and the provider's account id
        self.fixes: dict[str, dict] = {}
        self.instances: dict[str, str] = {}   # provider instance id -> the device AWS or OCI made for it
        self.seen: set[str] = set()
        self.refreshed: set[str] = set()
        self.count = 0

    @classmethod
    async def load(cls, db: AsyncSession, now: datetime, integration_id: str | None = None) -> "Saver":
        s = cls(db, now, integration_id)
        s.vulns = dict((await db.execute(select(Vulnerability.source_vuln_id, Vulnerability.id)
                                         .where(Vulnerability.source == SRC))).all())
        s.devices = dict((await db.execute(select(Device.source_id, Device.id)
                                           .where(Device.source == SRC))).all())
        s.instances = dict((await db.execute(select(CloudAsset.resource_id, CloudAsset.device_id)
                                             .where(CloudAsset.device_id.is_not(None)))).all())
        for sid, fid, st, det, fk, owner in (await db.execute(select(
                Finding.source_id, Finding.id, Finding.status, Finding.details, Finding.fix_key, Finding.integration_id)
                .where(Finding.source == SRC))).all():
            s.findings[sid] = (fid, st)
            s.owner[sid] = owner
            s.context[sid] = (det, fk)
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
        touch, reopen, refresh, context = [], [], [], []
        for row in rows:
            key, rid = str(row["insight_id"])[:128], str(row["resource_id"])[:256]
            fsid = f"{key}:{rid}"[:256]
            if fsid in self.seen:
                continue   # the API can list a resource twice under one insight
            self.seen.add(fsid)
            insight = insights[row["insight_id"]]
            vid, stmt = self._vuln(key, insight)
            if stmt is not None:
                refresh.append(stmt)
            det = details_for(row, insight, self.accounts)
            fk = fixes.key(SRC, key)
            if fk and fk not in self.fixes:
                self.fixes[fk] = fix_for(key, insight)[1]
            known = self.findings.get(fsid)
            if known is None:
                fid = str(uuid.uuid4())
                self.db.add(Finding(id=fid, device_id=self._device(rid, row), vuln_id=vid, source=SRC,
                                    source_id=fsid, integration_id=self.integration_id, status=FindingStatus.open,
                                    details=det, fix_key=fk,
                                    first_detected=r7.parse_dt(row.get("identified_at")), last_seen=self.now))
                self.findings[fsid] = (fid, FindingStatus.open)
            else:
                fid, status = known
                touch.append(fid)
                old_det, old_fk = self.context.get(fsid, (None, None))
                if old_det != det or old_fk != fk:   # only what changed is rewritten (the details are encrypted)
                    context.append({"b_id": fid, "b_details": det, "b_fix": fk})
                if status == FindingStatus.remediated:
                    reopen.append(fid)   # it came back, sadly
                    self.findings[fsid] = (fid, FindingStatus.open)
            self.count += 1
        await self.db.flush()
        for stmt in refresh:
            await self.db.execute(stmt)
        for i in range(0, len(touch), 1000):
            await self.db.execute(update(Finding).where(Finding.id.in_(touch[i:i + 1000])).values(last_seen=self.now))
        if self.integration_id:   # claim untagged rows (from before findings were tagged); never another tenant's
            for i in range(0, len(touch), 1000):
                await self.db.execute(update(Finding).where(Finding.id.in_(touch[i:i + 1000]), Finding.integration_id.is_(None))
                                      .values(integration_id=self.integration_id))
        if context:
            t = Finding.__table__
            await self.db.execute(update(t).where(t.c.id == bindparam("b_id"))
                                  .values(details=bindparam("b_details"), fix_key=bindparam("b_fix")), context)
        for i in range(0, len(reopen), 1000):
            await self.db.execute(update(Finding).where(Finding.id.in_(reopen[i:i + 1000]))
                                  .values(status=FindingStatus.open))
        await self.db.commit()

    async def save_fixes(self) -> None:
        """The fix catalog rows for every check seen this run (title and Rapid7's remediation steps)."""
        await fixes.save(self.db, {k: v for k, v in self.fixes.items() if v})
        await self.db.commit()

    def _ours(self, fsid: str, acct: str) -> bool:
        """The stored finding names the same provider account this tenant reads under that tool account number."""
        stored = (self.context.get(fsid, (None, None))[0] or {}).get("account_id")
        mine = (self.accounts.get(acct) or {}).get("account_id")
        return bool(stored and mine and stored == mine)

    async def close_missing(self, done: set[str], listed: set[str] | None, shared: bool = False) -> int:
        """Close open findings the tenant stopped listing: in a fully read account, or one it no longer has.
        shared: another tenant's findings live in the same table under overlapping account numbers, so only
        findings proven to be this tenant's (same provider account) close, and a missing account closes nothing."""
        gone = []
        for fsid, (fid, status) in self.findings.items():
            if fsid in self.seen or status not in _OPEN:
                continue
            owner = self.owner.get(fsid)
            if owner and self.integration_id and owner != self.integration_id:
                continue   # another integration reported it: only its own pass may close it
            mine = owner is not None and owner == self.integration_id   # tagged as this integration's own
            acct = account_of(fsid)
            if acct in done:
                if not shared or mine or self._ours(fsid, acct):
                    gone.append(fid)
            elif (not shared or mine) and listed is not None and acct is not None and acct not in listed:
                gone.append(fid)
        for i in range(0, len(gone), 1000):
            await self.db.execute(update(Finding).where(Finding.id.in_(gone[i:i + 1000]))
                                  .values(status=FindingStatus.remediated))
        await self.db.commit()
        return len(gone)
