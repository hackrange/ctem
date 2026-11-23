"""Third-party risk widgets (FairTPRM suppliers): the security score percentage by calendar quarter, for a tier or
one vendor. A quarter's number is each supplier's score as of the quarter's last day (today for the current one),
averaged across the suppliers that had a score then (api/core/tprm_scores.py)."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from api.core import tprm_scores as ts
from api.dashboards import fleet
from api.dashboards.catalog import Metric, Param, metric
from api.dashboards.m_risk import QUARTERS, quarter_bounds
from api.models.risk import ThirdPartyRisk

TIER = Param("tier", "Vendor tier", ("any", "tier1", "tier2", "tier3"),
             labels={"any": "All tiers", "tier1": "Tier 1", "tier2": "Tier 2", "tier3": "Tier 3"})
VENDOR = Param("vendor", "One vendor (optional)", pattern=r"[\w .,&'()/+@-]{1,128}",
               hint="vendor name as in TPRM; part of it is fine if only one vendor matches")
QUARTER = Param("quarter", "Quarter of this year", ("current", "q1", "q2", "q3", "q4"),
                labels={"current": "This quarter", "q1": "Q1 (Jan 1 to Mar 31)", "q2": "Q2 (Apr 1 to Jun 30)",
                        "q3": "Q3 (Jul 1 to Sep 30)", "q4": "Q4 (Oct 1 to Dec 31)"})


async def _suppliers(ctx, p) -> tuple[list, str | None]:
    """The suppliers the card is about, and a note when a named vendor matched none or several."""
    q = select(ThirdPartyRisk.id, ThirdPartyRisk.supplier_name)
    if p.get("tier", "any") != "any":
        q = q.where(ThirdPartyRisk.tier == p["tier"])
    name = (p.get("vendor") or "").strip()
    if not name:
        return (await ctx.db.execute(q)).all(), None
    exact = (await ctx.db.execute(q.where(func.lower(ThirdPartyRisk.supplier_name) == name.lower()))).all()
    if exact:
        return exact[:1], None
    like = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    some = (await ctx.db.execute(q.where(ThirdPartyRisk.supplier_name.ilike(f"%{like}%", escape="\\"))
                                 .order_by(ThirdPartyRisk.supplier_name).limit(6))).all()
    if len(some) == 1:
        return some, None
    if not some:
        return [], f"No vendor matches \"{name}\""
    return [], f"\"{name}\" matches {len(some) if len(some) < 6 else 'several'} vendors: " + \
        ", ".join(r[1] for r in some[:5]) + "; use the full name"


async def _score_quarter(ctx, p):
    q, now = p["quarter"], fleet.now()
    if q == "current":
        q = f"q{(now.month - 1) // 3 + 1}"
    a, b = quarter_bounds(now.year, q)
    label = f"{q.upper()} {now.year} ({QUARTERS[q][1]})"
    if a > now:
        return {"value": None, "unit": "%", "max": 100, "note": f"{label}: hasn't started yet"}
    rows, why = await _suppliers(ctx, p)
    if why:
        return {"value": None, "unit": "%", "max": 100, "note": why}
    end = min(b, now) - timedelta(microseconds=1) if b <= now else now
    prev = {"q1": "q4", "q2": "q1", "q3": "q2", "q4": "q3"}[q]
    _, prev_end = quarter_bounds(now.year - (1 if q == "q1" else 0), prev)
    points = await ts.points_for(ctx.db, [str(r[0]) for r in rows], end)

    def avg(when):
        got = [s for s in (ts.score_at(points[str(r[0])], when) for r in rows) if s is not None]
        return (round(sum(got) / len(got), 1) if got else None), len(got)
    cur, n = avg(end)
    was, _ = avg(prev_end - timedelta(microseconds=1))
    who = rows[0][1] if p.get("vendor") else {"any": "All vendors", "tier1": "Tier 1 vendors", "tier2": "Tier 2 vendors",
                                              "tier3": "Tier 3 vendors"}[p.get("tier", "any")]
    when = "so far (today)" if b > now else f"as of {QUARTERS[q][1].split(' to ')[1]}"
    if cur is None:
        note = f"{who}, {label}: no score on record {when}"
    elif p.get("vendor"):
        note = f"{who}, {label}, {when}"
    else:
        unscored = len(rows) - n
        note = f"{who}, {label}, {when}: average of {n:,} scored vendor{'' if n == 1 else 's'}" + \
            (f" ({unscored:,} without a score)" if unscored else "")
    return {"value": cur, "unit": "%", "max": 100, "delta": fleet.delta(cur, was, better="up"), "href": "/grc", "note": note}


C = "Third-party risk"
metric(Metric("tprm.score_quarter", "Vendor security score by calendar quarter", C, "value", (QUARTER, TIER, VENDOR), _score_quarter,
              "The vendors' security score percentage (as TPRM shows it) at the end of one calendar quarter of this year "
              "(Q1 to Q4), averaged across a tier or for one named vendor, with the change from the quarter before. "
              "Use one card per quarter.", needs="grc", filterable=False))
