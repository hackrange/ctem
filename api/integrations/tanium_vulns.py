"""Tanium Comply's CVE findings, with their proof (the OVAL test that matched: file, version found, version range).

Each endpoint's whole list comes back each sync, so per machine: new CVEs become findings, ones Tanium no longer
reports are closed, returning ones reopen. A machine with no results (not scanned yet, or Comply unavailable) is left
as it was: no answer is not a fix. A CVE excepted in Tanium is treated as not reported."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.tanium")

SOURCE = "tanium"
_PAGE = 100
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_FIELDS = ("name compliance { cveFindings { cveId severityV3 cvssScoreV3 cvssScore epssScore isCisaKev cisaDateAdded "
           "firstFound lastFound excepted detectedProducts detectedCPEs remediation "
           "tests { testId testResult actualValues expectedStates } } }")


def _day(v) -> datetime | None:
    try:
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


_PROFILE = re.compile(r"(?i)([\\/](?:users|home|documents and settings)[\\/])[^\\/,=]+")


def _masked(v) -> str:
    """A path with the person's profile folder masked (C:\\Users\\...\\AppData): the proof, without the name."""
    return _PROFILE.sub(r"\1...", str(v or ""))


def proof(f: dict) -> dict:
    """The evidence, trimmed: what Tanium checked, what it found and the vulnerable range."""
    tests = [{"found": _masked(t.get("actualValues"))[:400], "expected": str(t.get("expectedStates") or "")[:300]}
             for t in f.get("tests") or [] if str(t.get("testResult")).lower() == "true" and t.get("actualValues")][:3]
    return {"tool": "Tanium", "scan": str(f.get("scanType") or "oval")[:16],
            "products": [str(p)[:120] for p in f.get("detectedProducts") or [] if p and not p.startswith("[")][:5],
            "cpes": [str(c)[:160] for c in f.get("detectedCPEs") or [] if c and c.startswith("cpe:")][:5],
            "tests": tests, "remediation": str(f.get("remediation") or "")[:600] or None,
            "first_found": str(f.get("firstFound") or "")[:10] or None, "last_found": str(f.get("lastFound") or "")[:10] or None}


def reported(node: dict) -> dict[str, dict] | None:
    """{CVE: finding} for one endpoint (an excepted one as {"excepted": True}), or None when Tanium has no results."""
    got = {}
    for f in (node.get("compliance") or {}).get("cveFindings") or []:
        cve = str(f.get("cveId") or "").upper()
        if _CVE.fullmatch(cve):
            got[cve] = {"excepted": True} if f.get("excepted") else f
    return got or None


async def _catalog(db: AsyncSession, found: dict[str, dict]) -> dict[str, str]:
    """{CVE: Vulnerability.id} for Tanium's catalog rows, made or refreshed for these CVEs."""
    from api.models.vuln import Vulnerability
    have = {}
    cves = list(found)
    for i in range(0, len(cves), 500):
        for v in (await db.execute(select(Vulnerability).where(Vulnerability.source == SOURCE,
                                                               Vulnerability.source_vuln_id.in_(cves[i:i + 500])))).scalars():
            have[v.source_vuln_id] = v
    for cve, f in found.items():
        v = have.get(cve)
        cvss = float(f.get("cvssScoreV3") or f.get("cvssScore") or 0.0)
        kev, epss = bool(f.get("isCisaKev")), f.get("epssScore")
        product = next((p for p in f.get("detectedProducts") or [] if p and not p.startswith("[")), None)
        if v is None:
            v = Vulnerability(source=SOURCE, source_vuln_id=cve, cve_id=cve, cve_ids=[cve],
                              title=(f"{product}: {cve}" if product else cve)[:512])
            db.add(v)
            have[cve] = v
        if v.cvss_base != cvss or bool(v.is_kev) != kev or (epss is not None and v.epss_score != float(epss)):
            v.cvss_base, v.is_kev = cvss, kev
            if epss is not None:
                v.epss_score, v.epss_updated_at = float(epss), datetime.now(timezone.utc)
            v.score_inputs_at = datetime.now(timezone.utc)
    await db.flush()
    return {c: str(v.id) for c, v in have.items()}


async def sync(gw, db: AsyncSession, integration_id: str | None, listed: set[str]) -> int:
    """listed: the devices Tanium's endpoint list had this run; machines not on it are retired and their findings close."""
    from api.core.device_match import find_devices
    from api.models.vuln import Finding, FindingStatus
    from api.scoring.dirty import mark_devices
    count = 0
    async for page in gw.pages("endpoints", _FIELDS, _PAGE):
        per = {p["name"]: reported(p) for p in page if p.get("name")}
        hit = await find_devices(db, [n for n, r in per.items() if r])
        found = {c: f for r in per.values() if r for c, f in r.items() if not f.get("excepted")}
        vids = await _catalog(db, found)
        devs = {str(hit[n].id): r for n, r in per.items() if r and n in hit}
        existing: dict[str, dict[str, Finding]] = {}
        ids = list(devs)
        for i in range(0, len(ids), 200):
            for f in (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.device_id.in_(ids[i:i + 200])))).scalars():
                existing.setdefault(str(f.device_id), {})[f.vuln_id] = f
        changed, now = set(), datetime.now(timezone.utc)
        for dev, rep in devs.items():
            want = {vids[c]: f for c, f in rep.items() if c in vids and not f.get("excepted")}
            mine = existing.get(dev, {})
            for vid, f in want.items():
                row = mine.get(vid)
                last = _day(f.get("lastFound")) or now
                if row is None:
                    db.add(Finding(device_id=dev, vuln_id=vid, source=SOURCE, source_id=f"{dev}:{f.get('cveId')}"[:256],
                                   integration_id=integration_id, status=FindingStatus.open, details={"proof": proof(f)},
                                   first_detected=_day(f.get("firstFound")) or now, last_seen=last, exposure="local"))
                    changed.add(dev)
                    count += 1
                    continue
                if row.integration_id not in (None, integration_id):
                    continue   # another Tanium integration's
                if row.status == FindingStatus.remediated or (row.status == FindingStatus.merged and row.closed_at):
                    row.status, row.closed_at, row.closed_note = FindingStatus.open, None, None
                    row.details = {"proof": proof(f)}
                    changed.add(dev)
                if row.last_seen is None or row.last_seen.date() != last.date():
                    row.last_seen = last
                count += 1
            for vid, row in mine.items():
                if vid not in want and row.status in (FindingStatus.open, FindingStatus.merged) and row.closed_at is None \
                        and row.integration_id in (None, integration_id):
                    row.status, row.closed_at = FindingStatus.remediated, now   # Tanium checked again and no longer finds it
                    row.closed_note = "Excepted in Tanium" if any(vids.get(c) == vid for c, x in rep.items() if x.get("excepted")) else None
                    changed.add(dev)
        await db.commit()
        if changed:
            await mark_devices(db, list(changed))
            await db.commit()
        db.expunge_all()
    await _close_gone(db, integration_id, listed)
    return count


async def _close_gone(db: AsyncSession, integration_id: str | None, listed: set[str]) -> None:
    """Machines no longer in Tanium's endpoint list (retired): their open findings close. A listed machine with no
    results this time is left as it was."""
    from api.models.vuln import Finding, FindingStatus
    live = (FindingStatus.open, FindingStatus.merged)
    gone = [str(d) for (d,) in (await db.execute(select(Finding.device_id).distinct().where(
        Finding.source == SOURCE, Finding.status.in_(live), Finding.closed_at.is_(None),
        Finding.integration_id == integration_id))).all() if str(d) not in listed]
    from api.scoring.dirty import mark_devices
    await mark_devices(db, gone)   # a bulk statement: the flush hook can't see it
    for i in range(0, len(gone), 500):
        await db.execute(update(Finding).where(Finding.source == SOURCE, Finding.device_id.in_(gone[i:i + 500]),
                                               Finding.status.in_(live), Finding.closed_at.is_(None),
                                               Finding.integration_id == integration_id)
                         .values(status=FindingStatus.remediated, closed_at=datetime.now(timezone.utc))
                         .execution_options(synchronize_session=False))
    await db.commit()
