"""Vulnerabilities by calendar quarter: open at quarter end, found, fixed, or mean days to fix, against the quarter before."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import and_, func, or_, select

from api.dashboards import fleet
from api.dashboards.catalog import Metric, Param, metric
from api.dashboards.m_risk import QUARTERS, _mttr_between, quarter_bounds
from api.dashboards.m_vulns import FILTERS, KEV, SEVERITY, _roll, _w
from api.models.vuln import Finding, FindingStatus, Vulnerability

QUARTER = Param("quarter", "Quarter of this year", ("current", "q1", "q2", "q3", "q4"),
                labels={"current": "This quarter", "q1": "Q1 (Jan 1 to Mar 31)", "q2": "Q2 (Apr 1 to Jun 30)",
                        "q3": "Q3 (Jul 1 to Sep 30)", "q4": "Q4 (Oct 1 to Dec 31)"})
MEASURE = Param("measure", "Number", ("open", "new", "fixed", "mttr"),
                labels={"open": "Open at the end of the quarter", "new": "Found in the quarter",
                        "fixed": "Fixed in the quarter", "mttr": "Mean days to remediate"})
# Which way is good news, and how the card reads
BETTER = {"open": "down", "new": "down", "fixed": "up", "mttr": "down"}
NOTE = {"open": "open at quarter end", "new": "found", "fixed": "fixed", "mttr": "mean days to remediate"}
REAL = (FindingStatus.open, FindingStatus.in_progress, FindingStatus.remediated, FindingStatus.risk_accepted)


async def _count(ctx, w, m: str, a: datetime, b: datetime, roll=None) -> int:
    """Open at b (found before b and not fixed by then), found in [a, b), or fixed in [a, b). Rolled-up removed
    findings count in: each was found on one day and fixed on a later one."""
    fixed = Finding.status == FindingStatus.remediated
    cond = {
        "open": and_(Finding.first_detected < b, or_(Finding.status.in_((FindingStatus.open, FindingStatus.in_progress)),
                                                     and_(fixed, Finding.last_seen >= b))),
        "new": and_(Finding.first_detected >= a, Finding.first_detected < b, Finding.status.in_(REAL)),
        "fixed": and_(fixed, Finding.last_seen >= a, Finding.last_seen < b),
    }[m]
    n = (await ctx.db.execute(select(func.count()).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                              .where(*w, cond))).scalar_one()
    if roll is not None:
        from api.core import finding_history as fh
        n += (await fh.count(ctx.db, roll, "new", None, b) - await fh.count(ctx.db, roll, "fixed", None, b) if m == "open"
              else await fh.count(ctx.db, roll, m, a, b))
    return n


async def _value(ctx, w, m: str, a: datetime, b: datetime, roll=None):
    if m == "mttr":
        v, _ = await _mttr_between(ctx, w + [Finding.status == FindingStatus.remediated, Finding.first_detected.is_not(None)], a, b, roll)
        return v
    return await _count(ctx, w, m, a, b, roll)


async def _quarter(ctx, p):
    q, m, now = p["quarter"], p["measure"], fleet.now()
    if q == "current":
        q = f"q{(now.month - 1) // 3 + 1}"
    a, b = quarter_bounds(now.year, q)
    label = f"{q.upper()} {now.year} ({QUARTERS[q][1]})"
    unit = " days" if m == "mttr" else None
    if a > now:
        return {"value": None, "unit": unit, "note": f"{label}: hasn't started yet"}
    w, roll = _w(ctx, p), _roll(ctx, p)
    cur = await _value(ctx, w, m, a, min(b, now), roll)
    prev = {"q1": "q4", "q2": "q1", "q3": "q2", "q4": "q3"}[q]
    pa, pb = quarter_bounds(now.year - (1 if q == "q1" else 0), prev)
    was = await _value(ctx, w, m, pa, pb, roll)
    so_far = " so far" if b > now else ""
    from api.models.integration import SyncJob
    began = (await ctx.db.execute(select(func.min(SyncJob.started_at)))).scalar_one()
    began = began.replace(tzinfo=a.tzinfo) if began is not None and began.tzinfo is None else began
    # Before CTEM's first sync, only what was still open then is known; fixes made before it aren't recorded
    early = f". CTEM began syncing {began:%b %d, %Y}, so earlier fixes aren't recorded and this reads low" \
        if began is not None and (b < began if m == "open" else pa < began) else ""
    href = {"open": "/vulns", "new": "/vulns", "fixed": "/vulns/dashboard", "mttr": "/vulns/dashboard"}[m]   # fixed work is on its trend and MTTR charts
    return {"value": cur, "unit": unit, "delta": fleet.delta(cur, was, BETTER[m]), "href": href,
            "note": f"{label}{so_far}: {NOTE[m]}{early}"}


metric(Metric("vuln.quarter", "Vulnerabilities by calendar quarter", "Vulnerabilities", "value",
              (QUARTER, MEASURE, SEVERITY, KEV, *FILTERS), _quarter,
              "One quarter of this year: findings open at its end, found or fixed in it, or mean days to remediate, "
              "against the quarter before. Add a widget filter (Device type is Server, say) to split by asset."))
