"""Falcon Spotlight vulnerabilities from the shipper: each one a finding on its host (by Falcon's host id, then
hostname), under its own source so it never merges with a scanner's. A full pass mirrors Falcon: open findings
it no longer lists are closed; an incremental pass applies what changed (closed ones close)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.core import fixes

SOURCE = "crowdstrike_spotlight"
_AV = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
_OPEN = {"open", "reopen"}


def _dt(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None


def _av(vector: str | None) -> str | None:
    m = re.search(r"\bAV:([NALP])\b", vector or "")
    return _AV.get(m.group(1)) if m else None


async def _catalog(db: AsyncSession, cves: list[dict]) -> dict[str, str]:
    from api.models.vuln import Vulnerability
    ids = [c["id"] for c in cves]
    have = {v.source_vuln_id: v for v in (await db.execute(select(Vulnerability).where(
        Vulnerability.source == SOURCE, Vulnerability.source_vuln_id.in_(ids)))).scalars()}
    for c in cves:
        v = have.get(c["id"])
        if v is None:
            v = Vulnerability(source=SOURCE, source_vuln_id=c["id"], cve_id=c["id"], title=c.get("name") or c["id"], domain="infra")
            db.add(v)
            have[c["id"]] = v
        v.title = (c.get("name") or v.title or c["id"])[:512]
        v.description = c.get("description") or v.description
        if c.get("base_score") is not None:
            v.cvss_base = c["base_score"]
        v.cvss_vector = c.get("vector") or v.cvss_vector
        v.attack_vector = _av(c.get("vector")) or v.attack_vector
        v.is_kev = bool(c.get("is_kev")) or v.is_kev
        v.exploit_available = bool(c.get("exploit_status")) or v.exploit_available
        v.threat_actors = c.get("actors") or None
        v.exprt_rating = (c.get("exprt_rating") or "")[:16] or None
    await db.flush()
    return {k: str(v.id) for k, v in have.items()}


async def upsert(db: AsyncSession, cves: list[dict], vulns: list[dict], integration_id: str | None = None) -> int:
    from api.core.device_match import add_source, find_device
    from api.models.device import Device
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    if not vulns:
        return 0
    known = await _catalog(db, cves)
    missing = sorted({v["cve_id"] for v in vulns} - set(known))
    if missing:   # CVEs sent in an earlier batch of this run
        for vid, ref in (await db.execute(select(Vulnerability.id, Vulnerability.source_vuln_id).where(
                Vulnerability.source == SOURCE, Vulnerability.source_vuln_id.in_(missing)))).all():
            known[ref] = str(vid)
    aids = sorted({v["aid"] for v in vulns})
    by_aid = {d.edr_device_id: d for d in (await db.execute(select(Device).where(Device.edr_device_id.in_(aids)))).scalars()}
    now, n, found, catalog = datetime.now(timezone.utc), 0, {}, {}
    for v in vulns:
        dev = by_aid.get(v["aid"]) or (await find_device(db, v["hostname"]) if v.get("hostname") else None)
        vid = known.get(v["cve_id"])
        if dev is None or vid is None:
            continue
        by_aid[v["aid"]] = dev
        add_source(dev, SOURCE)
        sid = f"{v['aid']}:{v['cve_id']}"[:256]
        f = found.get(sid) or (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.source_id == sid))).scalar_one_or_none()
        if f is not None and integration_id and f.integration_id and f.integration_id != integration_id:
            continue   # another integration's finding: only its own runs may change or close it
        if f is None:
            f = Finding(device_id=str(dev.id), vuln_id=vid, source=SOURCE, source_id=sid, domain="infra")
            db.add(f)
        found[sid] = f
        if integration_id:
            f.integration_id = integration_id
        st = (v.get("status") or "").lower()
        f.status = FindingStatus.open if st in _OPEN else FindingStatus.remediated
        f.first_detected = _dt(v.get("created")) or f.first_detected or now
        f.last_seen = now if st in _OPEN else (_dt(v.get("closed")) or now)
        apps = list(dict.fromkeys([*(f.details or {}).get("apps", [])[:10], *(v.get("apps") or [])]))[:10] if sid in found else (v.get("apps") or [])
        f.details = {**(f.details or {}), "apps": apps, "spotlight_id": v.get("id")}
        rem = (v.get("remediation") or [None])[0]
        if rem and (rem.get("title") or rem.get("action")):
            key = fixes.key(SOURCE, re.sub(r"[^A-Za-z0-9_.-]", "_", (rem.get("title") or rem.get("action"))[:120]))
            if key:
                f.fix_key = key
                catalog[key] = {"source": SOURCE, "title": (rem.get("title") or rem.get("action"))[:512], "kind": "patch",
                                "steps": rem.get("action"), "links": [rem["link"]] if rem.get("link") else []}
        n += 1
    await fixes.save(db, catalog)   # the Fixes page: one row per remediation, once per batch
    await db.flush()
    return n


async def close_unseen(db: AsyncSession, started, integration_id: str) -> int:
    """After a full pass: open Spotlight findings Falcon no longer lists were fixed (or the host is gone). Only this
    integration's findings (and unclaimed ones from before findings were tagged): another tenant's pass closes nothing."""
    from sqlalchemy import or_
    from api.models.vuln import Finding, FindingStatus
    from api.scoring.dirty import mark_finding_devices
    which = (Finding.source == SOURCE, Finding.status == FindingStatus.open, Finding.last_seen < started,
             or_(Finding.integration_id == str(integration_id), Finding.integration_id.is_(None)))
    await mark_finding_devices(db, *which)
    r = await db.execute(update(Finding).where(*which)
                         .values(status=FindingStatus.remediated).execution_options(synchronize_session=False))
    return r.rowcount or 0
