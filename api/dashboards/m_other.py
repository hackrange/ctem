"""Exceptions, GRC and Cyber Threats widgets.

Exceptions: admin and cyber see every exception; anyone else sees their own requests.
GRC: people with GRC read access. Threats: admin and cyber (as the Cyber Threats page)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from api.dashboards.catalog import Metric, Param, metric
from api.models.vuln import ExceptionStatus, VulnException

RANGE = Param("range", "Range", ("30d", "7d", "90d", "180d"),
              labels={"7d": "7 days", "30d": "30 days", "90d": "90 days", "180d": "180 days"})
SEV_COLOR = {"critical": "--severity-critical", "high": "--severity-high", "medium": "--severity-medium",
             "low": "--severity-low", "informational": "--severity-info"}
RESULT_COLOR = {"pass": "--severity-low", "warn": "--severity-medium",  # nosec B105 -- check results, not a password
                "fail": "--severity-critical", "error": "--fg-muted"}


def _now():
    return datetime.now(timezone.utc)


def _mine(ctx) -> list:
    return [] if ctx.decider else [VulnException.requested_by_id == str(ctx.user.id)]


async def _exc_counts(ctx, p):
    now, S = _now(), ExceptionStatus
    q = select(func.count().filter(VulnException.status == S.approved, VulnException.expires_at > now),
               func.count().filter(VulnException.status == S.pending),
               func.count().filter(VulnException.status == S.approved, VulnException.expires_at > now,
                                   VulnException.expires_at <= now + timedelta(days=14)),
               func.count().filter(VulnException.status == S.rejected, VulnException.decided_at >= now - timedelta(days=30))
               ).select_from(VulnException).where(*_mine(ctx))
    a, pend, soon, rej = (await ctx.db.execute(q)).one()
    return {"items": [{"name": "Active", "value": a, "href": "/exceptions", "color": "--severity-low"},
                      {"name": "Waiting for approval", "value": pend, "href": "/exceptions", "color": "--severity-medium"},
                      {"name": "Ending in 14 days", "value": soon, "href": "/exceptions", "color": "--severity-high"},
                      {"name": "Rejected (30 days)", "value": rej, "href": "/exceptions", "color": "--severity-critical"}]}


async def _exc_ending(ctx, p):
    now = _now()
    from sqlalchemy.orm import selectinload
    rows = (await ctx.db.execute(select(VulnException).options(selectinload(VulnException.vuln)).where(
        VulnException.status == ExceptionStatus.approved, VulnException.expires_at > now, *_mine(ctx))
        .order_by(VulnException.expires_at).limit(p["limit"]))).scalars().all()
    return {"columns": ["Vulnerability", "Covers", "Ends", "Requested by"],
            "rows": [[(e.vuln.cve_id or e.vuln.title[:60]) if e.vuln else f"Rule: {(e.name or '')[:56]}", e.scope.value.replace("_", " "),
                      e.expires_at.date().isoformat(), e.requested_by] for e in rows],
            "hrefs": [f"/exceptions?id={e.id}" for e in rows]}


async def _checks(ctx):
    from api.routes.grc_data import latest_results
    from api.rules.custom import all_checks
    checks, latest = await all_checks(ctx.db), await latest_results(ctx.db)
    return [(t, c.name, latest.get(t)) for t, c in sorted(checks.items(), key=lambda kv: kv[1].name)]


async def _check_status(ctx, p):
    counts = Counter((r.result if r else "not run") for _, _, r in await _checks(ctx))
    return {"items": [{"name": k.replace("_", " ").title(), "value": n, "href": "/grc", "color": RESULT_COLOR.get(k)}
                      for k, n in counts.most_common()]}


async def _check_table(ctx, p):
    rows = await _checks(ctx)
    if p["only"] == "problems":
        rows = [r for r in rows if r[2] is None or r[2].result != "pass"]
    return {"columns": ["Control check", "Result", "Summary"],
            "rows": [[name, r.result if r else "not run", (r.summary if r else "")[:160]] for _, name, r in rows],
            "hrefs": [f"/grc/checks/{t}" for t, _, _ in rows]}


async def _frameworks(ctx, p):
    from api.models.grc import GrcAssessment
    from api.routes.grc_assess import _newest
    rows = sorted((await ctx.db.execute(select(GrcAssessment))).scalars().all(), key=_newest, reverse=True)
    latest = next((a for a in rows if a.status == "completed"), rows[0] if rows else None)
    fw = [f for f in (latest.framework_compliance or []) if isinstance(f, dict) and f.get("total_mapped")] if latest else []
    return {"items": [{"name": str(f.get("code") or f.get("name") or "")[:40], "value": round(float(f.get("compliance_pct") or 0), 1),
                       "href": "/grc"} for f in fw], "unit": "%",
            "note": f"From {latest.assessment_ref or ''} {latest.title}".strip() if latest else "No assessment yet"}


async def _alerts(ctx, p) -> list[dict]:
    from api.routes.threat import _alerts as load
    days = {"7d": 7, "30d": 30, "90d": 90, "180d": 180}[p.get("range", "30d")]
    since = (_now() - timedelta(days=days)).isoformat()
    out = [a for a in await load(ctx.db) if (a.get("detected_at") or "") >= since]
    if p.get("open_only"):
        out = [a for a in out if (a.get("status") or "") != "closed"]
    return out


def _parts(counter: Counter, key: str, colors: dict | None = None) -> dict:
    return {"items": [{"name": (k or "unknown").replace("_", " "), "value": n, "color": (colors or {}).get(k),
                       "href": f"/threat?{key}={k}" if k else "/threat"} for k, n in counter.most_common(12)]}


async def _t_sev(ctx, p):
    return _parts(Counter(a.get("severity") for a in await _alerts(ctx, p)), "severity", SEV_COLOR)


async def _t_status(ctx, p):
    return _parts(Counter(a.get("status") for a in await _alerts(ctx, p)), "status")


async def _t_tactic(ctx, p):
    return _parts(Counter(a.get("tactic") for a in await _alerts(ctx, p) if a.get("tactic")), "q")


async def _t_time(ctx, p):
    alerts = await _alerts(ctx, p)
    days = {"7d": 7, "30d": 30, "90d": 90, "180d": 180}[p["range"]]
    today = _now().date()
    x = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    sevs = ("critical", "high", "medium", "low")
    grid = {s: dict.fromkeys(x, 0) for s in sevs}
    for a in alerts:
        d, s = (a.get("detected_at") or "")[:10], a.get("severity")
        if s in grid and d in grid[s]:
            grid[s][d] += 1
    return {"x": x, "series": [{"name": s.title(), "data": list(grid[s].values()), "stack": "alerts", "color": SEV_COLOR[s]}
                               for s in sevs]}


async def _t_hosts(ctx, p):
    c = Counter(a.get("hostname") for a in await _alerts(ctx, p) if a.get("hostname"))
    rows = c.most_common(p["limit"])
    return {"columns": ["Host", "Alerts"], "rows": [[h, n] for h, n in rows], "hrefs": [f"/threat?q={h}" for h, _ in rows]}


async def _t_count(ctx, p):
    n = len(await _alerts(ctx, p))
    return {"value": n, "href": "/threat", "note": "Open alerts" if p.get("open_only") else "Alerts"}


LIMIT = Param("limit", "Rows", low=3, high=25, default=10)
OPEN = Param("open_only", "Open alerts only (not closed)", default=True)
E, G, T = "Exceptions", "GRC", "Cyber Threats"
metric(Metric("exceptions.counts", "Exceptions at a glance", E, "parts", (), _exc_counts,
              "Active, waiting, ending soon and recently rejected (your own requests unless you're admin or cyber).",
              per_user=True))
metric(Metric("exceptions.ending", "Exceptions ending soonest", E, "table", (LIMIT,), _exc_ending, per_user=True))
metric(Metric("grc.check_status", "Control checks by result", G, "parts", (), _check_status, needs="grc"))
metric(Metric("grc.checks", "Control check results", G, "table",
              (Param("only", "Show", ("all", "problems"), labels={"all": "Every check", "problems": "Only warnings and failures"}),),
              _check_table, needs="grc"))
metric(Metric("grc.frameworks", "Compliance by framework", G, "parts", (), _frameworks,
              "From the latest FairTPRM assessment.", needs="grc"))
metric(Metric("threats.count", "Alert count", T, "value", (RANGE, OPEN), _t_count, needs="threats"))
metric(Metric("threats.over_time", "Alerts over time", T, "series", (RANGE, OPEN), _t_time, needs="threats"))
metric(Metric("threats.by_severity", "Alerts by severity", T, "parts", (RANGE, OPEN), _t_sev, needs="threats"))
metric(Metric("threats.by_status", "Alerts by status", T, "parts", (RANGE,), _t_status, needs="threats"))
metric(Metric("threats.by_tactic", "Alerts by MITRE tactic", T, "parts", (RANGE, OPEN), _t_tactic, needs="threats"))
metric(Metric("threats.top_hosts", "Hosts with the most alerts", T, "table", (RANGE, OPEN, LIMIT), _t_hosts, needs="threats"))
