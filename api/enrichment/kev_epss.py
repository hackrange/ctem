"""Flag CISA KEV entries and pull FIRST EPSS scores for every CVE we hold."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import date, datetime, timezone

from sqlalchemy import bindparam, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.models.vuln import Vulnerability

log = logging.getLogger("open-ctem.enrichment")

# Fixed public feeds; never built from config or user input
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_EPSS_BATCH = 100
_MAX_BYTES = 30 * 1024 * 1024
_T = Vulnerability.__table__  # Core table: executemany by CVE, not by primary key
_MIN_KEV_ENTRIES = 500  # a much smaller catalog means a bad download; don't clear flags on it


def parse_kev(body: dict) -> dict[str, date | None]:
    out: dict[str, date | None] = {}
    for row in body.get("vulnerabilities") or []:
        cve = str(row.get("cveID") or "").strip().upper()
        if not _CVE.match(cve):
            continue
        try:
            out[cve] = date.fromisoformat(str(row.get("dateAdded") or ""))
        except ValueError:
            out[cve] = None
    return out


def parse_epss(body: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for row in body.get("data") or []:
        cve = str(row.get("cve") or "").strip().upper()
        try:
            score = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        if _CVE.match(cve) and 0.0 <= score <= 1.0:
            out[cve] = score
    return out


async def _get_json(client, url: str, params: dict | None = None) -> dict:
    resp = await client.get(url, params=params, headers={"Accept": "application/json"})
    resp.raise_for_status()
    if len(resp.content) > _MAX_BYTES:
        raise ValueError("feed response too large")
    return resp.json()


async def _known_cves(db: AsyncSession) -> list[str]:
    rows = await db.execute(select(Vulnerability.cve_id).where(Vulnerability.cve_id.isnot(None)).distinct())
    return sorted({c.strip().upper() for c in rows.scalars() if c and _CVE.match(c.strip().upper())})


async def apply_kev(db: AsyncSession, kev: dict[str, date | None], cves: list[str]) -> int:
    hits = [c for c in cves if c in kev]
    if hits:
        await db.execute(
            update(_T).where(_T.c.cve_id == bindparam("c")).values(is_kev=True, kev_added_date=bindparam("d")),
            [{"c": c, "d": kev[c]} for c in hits],
        )
    if len(kev) >= _MIN_KEV_ENTRIES:
        # Rare, but CISA does remove entries
        await db.execute(
            update(Vulnerability).where(Vulnerability.is_kev.is_(True), Vulnerability.cve_id.notin_(list(kev)))
            .values(is_kev=False, kev_added_date=None).execution_options(synchronize_session=False)
        )
    await db.commit()
    return len(hits)


async def apply_epss(db: AsyncSession, scores: dict[str, float]) -> int:
    if not scores:
        return 0
    now = datetime.now(timezone.utc)
    await db.execute(
        update(_T).where(_T.c.cve_id == bindparam("c")).values(epss_score=bindparam("e"), epss_updated_at=now),
        [{"c": c, "e": s} for c, s in scores.items()],
    )
    await db.commit()
    return len(scores)


async def enrich(db: AsyncSession) -> dict:
    """Refresh KEV flags and EPSS scores. Each feed fails independently."""
    cves = await _known_cves(db)
    result = {"cves": len(cves), "kev": None, "epss": None}
    if not cves:
        return result
    async with safe_client(timeout=60.0) as client:
        try:
            result["kev"] = await apply_kev(db, parse_kev(await _get_json(client, KEV_URL)), cves)
        except Exception as e:
            await db.rollback()
            log.warning("KEV refresh failed: %s", type(e).__name__)
        try:
            scores: dict[str, float] = {}
            for i in range(0, len(cves), _EPSS_BATCH):
                chunk = cves[i:i + _EPSS_BATCH]
                body = await _get_json(client, EPSS_URL, {"cve": ",".join(chunk), "limit": len(chunk)})
                scores.update(parse_epss(body))
                await asyncio.sleep(0.2)  # be polite to a free API
            result["epss"] = await apply_epss(db, scores)
        except Exception as e:
            await db.rollback()
            log.warning("EPSS refresh failed: %s", type(e).__name__)
    log.info("enrichment: %s", result)
    return result
