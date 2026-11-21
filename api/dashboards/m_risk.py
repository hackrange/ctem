"""Risk widgets: the risk score, vulnerabilities and remediation over time against the risk score, mean time to
remediate (cloud vs on-prem), accepted risk, assets by their worst severity, top vulnerabilities split cloud vs
on-prem, and a CVSS-by-EPSS scatter. Open, new and fixed counts are rebuilt from finding dates (history from
day one); the risk score, accepted risk and severity mix come from daily snapshots (see snapshots.py)."""
from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import Date, case, cast, func, select

from api.core import vuln_dashboard as vd
from api.dashboards import fleet
from api.dashboards.catalog import Metric, Param, metric
from api.models.device import Device
from api.models.vuln import Finding, FindingStatus, Vulnerability

RANGE = Param("range", "Range", tuple(fleet.RANGE_DAYS), default="90d", labels=fleet.RANGE_LABEL)
BUCKET = Param("bucket", "Group by", fleet.BUCKETS, labels=fleet.BUCKET_LABEL)
SPLIT = Param("split", "Split", ("none", "cloud"), labels={"none": "All together", "cloud": "Cloud vs on-prem"})
WITH_RISK = Param("with_risk", "Add the risk score line", default=True)
SEV_COLOR = {"critical": "--severity-critical", "high": "--severity-high", "medium": "--severity-medium", "low": "--severity-low"}
CLOUD, ONPREM = "--accent", "--severity-info"


async def daily(ctx, cloud: bool | None = None) -> dict:
    """Open by severity, new and fixed per day over all history. cloud: True only cloud devices, False none."""
    if cloud is None and ctx.scope is None:
        return (await vd.cached(ctx.db, "all", None, None))["trend"]
    w = vd._where(None, None) + vd.scoped(ctx.scope)
    if cloud is not None:
        ids = Finding.device_id.in_(fleet.cloud_ids())
        w.append(ids if cloud else ~ids)
    return await vd._trend(ctx.db, w, None)


def _open(tr: dict) -> list[int]:
    return [sum(v) for v in zip(*(tr[s] for s in vd.SEVERITIES))] if tr["days"] else []


def _window(x: list, *series, days: int):
    return x[-days:], [s[-days:] for s in series]


async def _risk_line(ctx, x: list[str], unit: str) -> dict | None:
    if ctx.scope is not None:
        return None
    sx, s = await fleet.snaps(ctx.db, ["risk_avg_x10"], len(x))
    vals = [None if v is None else round(v / 10, 1) for v in s["risk_avg_x10"]]
    _, (vals,) = fleet.resample(sx, [vals], unit, ["avg"])
    return {"name": "Risk score", "data": vals, "type": "line", "axis": 1, "color": "--severity-high"}


async def _score(ctx, p):
    w = [Device.risk_score.is_not(None), *fleet.scoped(ctx)]
    avg = (await ctx.db.execute(select(func.avg(Device.risk_score)).where(*w))).scalar_one()
    cur = round(float(avg), 1) if avg is not None else None
    was = None
    if ctx.scope is None:
        v = await fleet.snap_on(ctx.db, "risk_avg_x10", date.today() - timedelta(days=30))
        was = round(v / 10, 1) if v is not None else None
    return {"value": cur, "max": 100, "href": "/devices?sort=risk_score", "delta": fleet.delta(cur, was),
            "note": "Average device risk (0 to 100)" + (f", was {was} a month ago" if was is not None else "")}


async def _vulns_vs_risk(ctx, p):
    days, unit = fleet.RANGE_DAYS[p["range"]], p["bucket"]
    if p["split"] == "cloud":
        cl, on = await daily(ctx, True), await daily(ctx, False)
        ca, oa = dict(zip(cl["days"], _open(cl))), dict(zip(on["days"], _open(on)))
        days_all = sorted(set(ca) | set(oa))   # each starts at its own first finding; before that it's 0
        a_all, b_all = [ca.get(d, 0) for d in days_all], [oa.get(d, 0) for d in days_all]
        x, (a, b) = _window(days_all, a_all, b_all, days=days)
        labels, (a2, b2) = fleet.resample(x, [a, b], unit, ["last", "last"])
        series = [{"name": "On-prem", "data": b2, "stack": "v", "color": ONPREM},
                  {"name": "Cloud", "data": a2, "stack": "v", "color": CLOUD}]
        total = [x1 + x2 for x1, x2 in zip(a_all, b_all)]
    else:
        tr = await daily(ctx)
        total = _open(tr)
        x, (o,) = _window(tr["days"], total, days=days)
        labels, (o2,) = fleet.resample(x, [o], unit, ["last"])
        series = [{"name": "Open findings", "data": o2, "color": ONPREM}]
    if p.get("with_risk"):
        line = await _risk_line(ctx, x, unit)
        if line:
            series.append(line)
    return {"x": labels, "series": series, "y2_unit": "risk", "headline": fleet.change(total, "open findings")}


async def _new_vs_fixed(ctx, p):
    days, unit = fleet.RANGE_DAYS[p["range"]], p["bucket"]
    tr = await daily(ctx)
    x, (n, f) = _window(tr["days"], tr["new"], tr["fixed"], days=days)
    labels, (n2, f2) = fleet.resample(x, [n, f], unit, ["sum", "sum"])
    series = [{"name": "New", "data": n2, "color": ONPREM}, {"name": "Remediated", "data": f2, "color": "--severity-low"}]
    if p.get("with_risk"):
        line = await _risk_line(ctx, x, unit)
        if line:
            series.append(line)
    month_new, month_fix = sum(tr["new"][-30:]), sum(tr["fixed"][-30:])
    return {"x": labels, "series": series, "y2_unit": "risk",
            "headline": f"{month_new:,} new and {month_fix:,} remediated in the last 30 days"}


async def _remediated(ctx, p):
    w = vd._where(None, None) + vd.scoped(ctx.scope)
    if p["range"] != "all":
        w.append(Finding.first_detected >= fleet.now() - timedelta(days=fleet.RANGE_DAYS[p["range"]]))
    fixed, open_ = (await ctx.db.execute(select(func.count().filter(Finding.status == FindingStatus.remediated),
                                                func.count().filter(Finding.status.in_(vd.OPEN))).where(*w))).one()
    total = fixed + open_
    return {"value": round(100 * fixed / total, 1) if total else None, "unit": "%", "max": 100, "better": "up",
            "note": f"{fixed:,} of {total:,} findings remediated", "href": "/vulns"}


async def _mttr_value(ctx, p):
    days = int(p["days"])
    w = vd._where(None, None) + vd.scoped(ctx.scope) + [Finding.status == FindingStatus.remediated,
                                                         Finding.first_detected.is_not(None)]
    sev = vd._sev()
    if p["severity"] != "any":
        w.append(sev == p["severity"])
    took = func.avg(func.extract("epoch", Finding.last_seen - Finding.first_detected) / 86400)
    end = fleet.now()

    async def period(a, b):
        v = (await ctx.db.execute(select(took).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                                  .where(*w, Finding.last_seen >= a, Finding.last_seen < b))).scalar_one()
        return round(float(v), 1) if v is not None else None
    cur = await period(end - timedelta(days=days), end)
    was = await period(end - timedelta(days=2 * days), end - timedelta(days=days))
    return {"value": cur, "unit": " days", "delta": fleet.delta(cur, was), "href": "/vulns?status=remediated",
            "note": f"Mean time to remediate, fixes in the last {days} days"}


async def _mttr_split(ctx, p):
    month = cast(func.date_trunc(p["bucket"], Finding.last_seen), Date)
    took = func.avg(func.extract("epoch", Finding.last_seen - Finding.first_detected) / 86400)
    is_cloud = case((Finding.device_id.in_(fleet.cloud_ids()), "cloud"), else_="onprem")
    rows = (await ctx.db.execute(select(month, is_cloud, took).where(
        *vd._where(None, None), *vd.scoped(ctx.scope), Finding.status == FindingStatus.remediated,
        Finding.first_detected.is_not(None), Finding.last_seen >= fleet.now() - timedelta(days=fleet.RANGE_DAYS[p["range"]]))
        .group_by(month, is_cloud))).all()
    xs = sorted({r[0] for r in rows})
    grid = {k: [None] * len(xs) for k in ("cloud", "onprem")}
    for m, k, v in rows:
        grid[k][xs.index(m)] = round(float(v or 0), 1)
    return {"x": [d.isoformat()[:7] if p["bucket"] == "month" else d.isoformat() for d in xs], "y_unit": "days",
            "series": [{"name": "Cloud", "data": grid["cloud"], "color": CLOUD},
                       {"name": "On-prem", "data": grid["onprem"], "color": ONPREM}]}


async def _accepted(ctx, p):
    w = [Finding.status.in_(vd.OPEN), *vd.scoped(ctx.scope)]
    score = func.coalesce(Finding.composite_score, 0.0)
    n, acc, allr = (await ctx.db.execute(select(func.count().filter(Finding.exception_id.is_not(None)),
                                                func.sum(score).filter(Finding.exception_id.is_not(None)), func.sum(score))
                                         .where(*w))).one()
    pct = round(100 * float(acc or 0) / float(allr), 2) if allr else None
    return {"value": pct, "unit": "%", "max": 100, "href": "/exceptions",
            "note": f"of open risk is accepted through exceptions ({n:,} findings)"}


async def _accepted_trend(ctx, p):
    if (e := fleet.fleet_only(ctx)):
        return e
    x, s = await fleet.snaps(ctx.db, ["accepted_findings", "accepted_risk_pct_x10"], fleet.RANGE_DAYS[p["range"]])
    pct = [None if v is None else v / 10 for v in s["accepted_risk_pct_x10"]]
    labels, (a, r) = fleet.resample(x, [s["accepted_findings"], pct], p["bucket"], ["last", "avg"])
    return {"x": labels, "y2_unit": "%", "headline": fleet.change(s["accepted_findings"], "accepted findings"),
            "series": [{"name": "Accepted findings", "data": a, "color": ONPREM},
                       {"name": "Accepted risk %", "data": r, "type": "line", "axis": 1, "color": "--severity-high"}],
            "note": "Builds from a daily snapshot." if sum(v is not None for v in a) < 3 else None}


async def _by_worst(ctx, p):
    if (e := fleet.fleet_only(ctx)):
        return e
    keys = [f"worst_{s}" for s in vd.SEVERITIES]
    x, s = await fleet.snaps(ctx.db, keys, fleet.RANGE_DAYS[p["range"]])
    labels, vals = fleet.resample(x, [s[k] for k in keys], p["bucket"], ["last"] * 4)
    total = [sum(v for v in col if v is not None) if any(v is not None for v in col) else None for col in zip(*(s[k] for k in keys))]
    return {"x": labels, "headline": fleet.change(total, "assets with open findings"),
            "series": [{"name": sv.title(), "data": v, "stack": "a", "color": SEV_COLOR[sv]} for sv, v in reversed(list(zip(vd.SEVERITIES, vals)))],
            "note": "Builds from a daily snapshot." if sum(v is not None for v in total) < 3 else None}


async def _top_split(ctx, p):
    order = (Vulnerability.is_kev.desc(), Vulnerability.cvss_base.desc().nulls_last(), Vulnerability.affected_devices.desc()) \
        if p["rank"] == "severity" else (Vulnerability.affected_devices.desc(),)
    if ctx.scope is None:
        top = (await ctx.db.execute(select(Vulnerability).where(Vulnerability.affected_devices > 0).order_by(*order)
                                    .limit(p["limit"]))).scalars().all()
    else:
        ids = select(Finding.vuln_id).where(Finding.status.in_(vd.OPEN), *vd.scoped(ctx.scope)).distinct()
        top = (await ctx.db.execute(select(Vulnerability).where(Vulnerability.id.in_(ids)).order_by(*order)
                                    .limit(p["limit"]))).scalars().all()
    ids = [v.id for v in top]
    is_cloud = Finding.device_id.in_(fleet.cloud_ids())
    counts = {r[0]: r[1:] for r in (await ctx.db.execute(
        select(Finding.vuln_id, func.count().filter(is_cloud), func.count().filter(~is_cloud))
        .where(Finding.vuln_id.in_(ids), *vd._where(None, None), Finding.status.in_(vd.OPEN), *vd.scoped(ctx.scope))
        .group_by(Finding.vuln_id))).all()} if ids else {}
    sev = lambda c: "Critical" if (c or 0) >= 9 else "High" if (c or 0) >= 7 else "Medium" if (c or 0) >= 4 else "Low"  # noqa: E731
    return {"columns": ["Vulnerability", "CVSS", "EPSS", "Exploit", "Cloud", "On-prem", "Severity"],
            "rows": [[f"{v.cve_id + ' ' if v.cve_id else ''}{v.title[:70]}", v.cvss_base,
                      f"{v.epss_score * 100:.1f}%" if v.epss_score is not None else None,
                      "KEV" if v.is_kev else ("Yes" if v.exploit_available else ""), *counts.get(v.id, (0, 0)), sev(v.cvss_base)]
                     for v in top],
            "hrefs": [f"/vulns/{v.id}" for v in top]}


async def _scatter(ctx, p):
    cols = (Vulnerability.id, Vulnerability.cve_id, Vulnerability.title, Vulnerability.cvss_base, Vulnerability.epss_score,
            Vulnerability.is_kev, Vulnerability.exploit_available)
    if ctx.scope is None:
        rows = (await ctx.db.execute(select(*cols, Vulnerability.affected_devices).where(
            Vulnerability.affected_devices > 0, Vulnerability.cvss_base.is_not(None))
            .order_by(Vulnerability.affected_devices.desc()).limit(p["limit"]))).all()
    else:
        n = func.count()
        rows = (await ctx.db.execute(select(*cols, n).join(Finding, Finding.vuln_id == Vulnerability.id).where(
            Finding.status.in_(vd.OPEN), Vulnerability.cvss_base.is_not(None), *vd.scoped(ctx.scope))
            .group_by(*cols).order_by(n.desc()).limit(p["limit"]))).all()
    groups = {"KEV": [], "Exploit available": [], "Other": []}
    for i, cve, title, cvss, epss, kev, expl, devs in rows:
        g = "KEV" if kev else "Exploit available" if expl else "Other"
        groups[g].append([cvss, round((epss or 0) * 100, 2), devs, f"{cve or ''} {title[:60]}".strip(), f"/vulns/{i}"])
    colors = {"KEV": "--severity-critical", "Exploit available": "--severity-high", "Other": "--severity-info"}
    return {"x_label": "CVSS", "y_label": "EPSS %", "size_label": "Devices",
            "groups": [{"name": k, "color": colors[k], "points": v} for k, v in groups.items() if v],
            "headline": "Top right is where to start: severe, likely to be exploited, and on many devices"}


C = "Risk and remediation"
TOP_RANK = Param("rank", "Rank by", ("devices", "severity"), labels={"devices": "Most devices", "severity": "KEV and CVSS first"})
metric(Metric("risk.score", "Risk score", C, "value", (), _score,
              "Average device risk score (0 to 100) with the change from a month ago. Looks good as a gauge."))
metric(Metric("risk.vulns_vs_risk", "Vulnerabilities vs risk score over time", C, "series", (RANGE, BUCKET, SPLIT, WITH_RISK),
              _vulns_vs_risk, "Open findings per week (optionally cloud vs on-prem) with the risk score as a line."))
metric(Metric("risk.new_vs_fixed", "New and remediated vs risk score", C, "series", (RANGE, BUCKET, WITH_RISK), _new_vs_fixed,
              "New and remediated findings per week with the risk score as a line."))
metric(Metric("risk.remediated_pct", "Remediated share", C, "value",
              (Param("range", "Findings detected in", ("all", "365d", "180d", "90d", "30d"),
                     labels={"all": "All time", **fleet.RANGE_LABEL}),), _remediated,
              "Share of findings that have been remediated. Looks good as a gauge."))
metric(Metric("risk.mttr", "Mean time to remediate", C, "value",
              (Param("days", "Fixes in the last", ("30", "90", "7", "180"), labels={"7": "7 days", "30": "30 days", "90": "90 days", "180": "180 days"}),
               Param("severity", "Severity", ("any", *vd.SEVERITIES), labels={"any": "Any severity"})), _mttr_value,
              "Average days from detection to fix, with the change from the period before."))
metric(Metric("risk.mttr_split", "Mean time to remediate, cloud vs on-prem", C, "series",
              (Param("range", "Range", ("365d", "180d", "90d"), labels=fleet.RANGE_LABEL),
               Param("bucket", "Group by", ("month", "week"), labels=fleet.BUCKET_LABEL)), _mttr_split))
metric(Metric("risk.accepted", "Accepted risk", C, "value", (), _accepted,
              "Share of open risk covered by approved exceptions. Looks good as a gauge."))
metric(Metric("risk.accepted_trend", "Accepted findings vs accepted risk over time", C, "series", (RANGE, BUCKET), _accepted_trend, filterable=False))
metric(Metric("risk.assets_by_severity", "Assets over time by worst severity", C, "series", (RANGE, BUCKET), _by_worst,
              "How many devices have a critical, high, medium or low finding as their worst, day by day.", filterable=False))
metric(Metric("risk.top_vulns_split", "Top vulnerabilities, cloud vs on-prem", C, "table",
              (Param("limit", "Rows", low=3, high=25, default=5), TOP_RANK), _top_split))
metric(Metric("risk.vuln_scatter", "Vulnerability risk map (CVSS vs EPSS)", C, "points",
              (Param("limit", "Vulnerabilities", low=25, high=500, default=200),), _scatter,
              "Each dot is a vulnerability: CVSS across, chance of exploitation up, size is how many devices have it."))
