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
    """Write only what changed, and mark those vulnerabilities for rescoring (api/scoring/dirty.py): the catalog
    holds 156,000 CVEs and almost none change from one run to the next."""
    now = datetime.now(timezone.utc)
    have = {(c or "").strip().upper(): (k, d) for c, k, d in (await db.execute(
        select(Vulnerability.cve_id, Vulnerability.is_kev, Vulnerability.kev_added_date).where(Vulnerability.cve_id.isnot(None)))).all()}
    hits = [c for c in cves if c in kev]
    flip = [c for c in hits if have.get(c, (False, None)) != (True, kev[c])]
    if flip:
        await db.execute(
            update(_T).where(_T.c.cve_id == bindparam("c")).values(is_kev=True, kev_added_date=bindparam("d"),
                                                                   score_inputs_at=now),
            [{"c": c, "d": kev[c]} for c in flip],
        )
    if len(kev) >= _MIN_KEV_ENTRIES:
        # Rare, but CISA does remove entries
        await db.execute(
            update(Vulnerability).where(Vulnerability.is_kev.is_(True), Vulnerability.cve_id.notin_(list(kev)))
            .values(is_kev=False, kev_added_date=None, score_inputs_at=now).execution_options(synchronize_session=False)
        )
    await db.commit()
    return len(hits)


async def apply_epss(db: AsyncSession, scores: dict[str, float], asked: list[str] | None = None) -> int:
    """New scores where they moved (marked for rescoring); asked = every CVE fetched, so it isn't fetched again today."""
    if not scores and not asked:
        return 0
    now = datetime.now(timezone.utc)
    have: dict[str, float | None] = {}
    keys = list(scores)
    for i in range(0, len(keys), 1000):   # one bind per CVE: the driver refuses more than 32,767 in a query
        have.update({(c or "").strip().upper(): e for c, e in (await db.execute(
            select(Vulnerability.cve_id, Vulnerability.epss_score).where(Vulnerability.cve_id.in_(keys[i:i + 1000])))).all()})
    moved = {c: s for c, s in scores.items() if have.get(c) is None or abs(have[c] - s) > 1e-9}
    # FIRST nudges almost every score daily; rescore only for a move that shifts a finding's score
    # (half a percentage point = 0.15 of 100); smaller drift is written and picked up by the daily full rescore
    big = {c: s for c, s in moved.items() if have.get(c) is None or abs(have[c] - s) >= EPSS_RESCORE_STEP}
    for batch, stamp in ((big, True), ({c: s for c, s in moved.items() if c not in big}, False)):
        if batch:
            vals = {"epss_score": bindparam("e"), "epss_updated_at": now, **({"score_inputs_at": now} if stamp else {})}
            await db.execute(update(_T).where(_T.c.cve_id == bindparam("c")).values(**vals),
                             [{"c": c, "e": s} for c, s in batch.items()])
    rest = [c for c in (asked or scores) if c not in moved]
    for i in range(0, len(rest), 1000):
        await db.execute(update(Vulnerability).where(Vulnerability.cve_id.in_(rest[i:i + 1000])).values(epss_updated_at=now)
                         .execution_options(synchronize_session=False))
    await db.commit()
    return len(scores)


EPSS_EVERY_HOURS = 20   # FIRST publishes once a day
EPSS_RESCORE_STEP = 0.005


async def _epss_due(db: AsyncSession, cves: list[str]) -> list[str]:
    """CVEs whose EPSS score is missing or older than a day's publication: the rest were asked about today."""
    from datetime import timedelta
    fresh = datetime.now(timezone.utc) - timedelta(hours=EPSS_EVERY_HOURS)

    def aware(dt):   # SQLite hands timestamps back without a zone; they were written in UTC
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    recent = {(c or "").strip().upper() for c, at in (await db.execute(
        select(Vulnerability.cve_id, Vulnerability.epss_updated_at).where(Vulnerability.epss_updated_at.isnot(None)))).all()
        if aware(at) >= fresh}
    return [c for c in cves if c not in recent]


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
        scores: dict[str, float] = {}
        answered: list[str] = []
        try:
            due = await _epss_due(db, cves)   # was all 156,000 every run: about 1,560 requests to a free API
            result["epss_asked"] = len(due)
            for i in range(0, len(due), _EPSS_BATCH):
                chunk = due[i:i + _EPSS_BATCH]
                try:
                    body = await _get_json(client, EPSS_URL, {"cve": ",".join(chunk), "limit": len(chunk)})
                except Exception as e:  # noqa: BLE001 -- FIRST refused or timed out (a rate limit, say): stop asking
                    log.warning("EPSS refresh stopped after %d of %d CVEs: %s; the rest are asked on the next run",
                                len(answered), len(due), type(e).__name__)
                    break
                got = parse_epss(body)
                scores.update(got)
                if got:   # FIRST answered for this batch: the rest of it has no score yet, ask again tomorrow
                    answered += chunk
                await asyncio.sleep(0.2)  # be polite to a free API
            # What was answered is kept even when a later request failed, so the next run carries on instead of
            # asking all of them again (a failure near the end cost every post-sync run its full 8 minutes)
            result["epss"] = await apply_epss(db, scores, answered)
        except Exception as e:
            await db.rollback()
            log.warning("EPSS refresh failed: %s", type(e).__name__)
    log.info("enrichment: %s", result)
    return result
