"""Vulnerability widgets. They reuse the Vuln Dashboard's queries; for fleet-wide viewers with no severity or KEV
filter they read its ready-made answer, so they load instantly."""
from __future__ import annotations

from sqlalchemy import and_, select

from api.core import vuln_dashboard as vd
from api.dashboards.catalog import Metric, Param, metric
from api.models.device import DeviceType
from api.models.vuln import Finding, Vulnerability

SEVERITY = Param("severity", "Severity", ("any", "critical_high", "critical", "high", "medium", "low"),
                 labels={"any": "Any severity", "critical_high": "Critical and high"})
SOURCE = Param("source", "Source", ("any", *vd.SOURCES), labels={"any": "All sources"})
DTYPE = Param("device_type", "Device type", ("any", *DeviceType.__members__), labels={"any": "All device types"})
KEV = Param("kev_only", "Known exploited (KEV) only", default=False)
RANGE = Param("range", "Range", ("90d", "30d", "180d", "365d", "all"),
              labels={"30d": "30 days", "90d": "90 days", "180d": "180 days", "365d": "1 year", "all": "All time"})
LIMIT = Param("limit", "Rows", low=3, high=25, default=10)
COLORS = {"critical": "--severity-critical", "high": "--severity-high", "medium": "--severity-medium", "low": "--severity-low"}
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
MEASURES = ("open", "critical", "high", "kev", "exploitable", "past_sla", "devices", "vulns", "new_7d", "fixed_7d", "excepted")
MEASURE_LABEL = {"open": "Open findings", "critical": "Critical findings", "high": "High findings", "kev": "KEV findings",
                 "exploitable": "Exploit available", "past_sla": "Past SLA", "devices": "Devices affected",
                 "vulns": "Distinct vulnerabilities", "new_7d": "New in 7 days", "fixed_7d": "Fixed in 7 days",
                 "excepted": "Excepted findings"}
MEASURE_HREF = {"open": "/vulns", "critical": "/vulns?min_cvss=9", "high": "/vulns?min_cvss=7", "kev": "/vulns?is_kev=true",
                "past_sla": "/grc/checks/ctem_vuln_sla", "excepted": "/exceptions", "devices": "/devices"}


def _sev_cond(sev: str):
    c = Vulnerability.cvss_base
    return {"critical": c >= 9.0, "high": and_(c >= 7.0, c < 9.0), "medium": and_(c >= 4.0, c < 7.0),
            "low": (c < 4.0) | c.is_(None), "critical_high": c >= 7.0}.get(sev)


def _w(ctx, p) -> list:
    w = vd._where(None if p.get("source") == "any" else p.get("source"),
                  None if p.get("device_type") == "any" else p.get("device_type")) + vd.scoped(ctx.scope)
    cond = _sev_cond(p.get("severity", "any"))
    if cond is not None:
        w.append(Finding.vuln_id.in_(select(Vulnerability.id).where(cond)))
    if p.get("kev_only"):
        w.append(Finding.vuln_id.in_(select(Vulnerability.id).where(Vulnerability.is_kev == True)))  # noqa: E712
    return w


async def _ready(ctx, p) -> dict | None:
    """The Vuln Dashboard's cached answer, when it covers this widget."""
    if ctx.scope is not None or p.get("severity", "any") != "any" or p.get("kev_only"):
        return None
    src = None if p.get("source") in (None, "any") else p["source"]
    dt = None if p.get("device_type") in (None, "any") else p["device_type"]
    return await vd.cached(ctx.db, p.get("range", "all"), src, dt)


async def _kpi(ctx, p):
    ready = await _ready(ctx, p)
    k = ready["kpis"] if ready else await vd._kpis(ctx.db, _w(ctx, p))
    m = p["measure"]
    out = {"value": k.get(m), "href": MEASURE_HREF.get(m), "note": MEASURE_LABEL[m]}
    if ready and m in ("open", "critical", "high", "kev") and p.get("severity", "any") == "any":
        tr = ready["trend"]
        daily = tr["kev"] if m == "kev" else tr[m] if m != "open" else [sum(v) for v in zip(*(tr[s] for s in vd.SEVERITIES))]
        if daily:
            out["spark"] = daily[-30:]
            if len(daily) > 30 and daily[-31]:
                out["delta"] = {"pct": round((daily[-1] - daily[-31]) / daily[-31] * 100, 1), "was": daily[-31], "better": "down"}
    return out


async def _trend_data(ctx, p) -> dict:
    ready = await _ready(ctx, p)
    return ready["trend"] if ready else await vd._trend(ctx.db, _w(ctx, p), vd.RANGES[p["range"]])


async def _trend(ctx, p):
    tr = await _trend_data(ctx, p)
    sevs = [s for s in vd.SEVERITIES if p.get("severity") in ("any", s) or (p.get("severity") == "critical_high" and s in ("critical", "high"))]
    series = [{"name": SEV_LABEL[s], "data": tr[s], "stack": "open", "color": COLORS[s]} for s in reversed(sevs)]
    if p.get("show_kev"):
        series.append({"name": "KEV", "data": tr["kev"], "color": "--fg"})
    return {"x": tr["days"], "series": series}


async def _flow(ctx, p):
    tr = await _trend_data(ctx, p)
    return {"x": tr["days"], "series": [{"name": "New", "data": tr["new"], "color": "--severity-high"},
                                        {"name": "Fixed", "data": tr["fixed"], "color": "--severity-low"}]}


async def _aging(ctx, p):
    ready = await _ready(ctx, p)
    a = ready["aging"] if ready else await vd._aging(ctx.db, _w(ctx, p))
    return {"x": a["buckets"], "series": [{"name": SEV_LABEL[s], "data": a[s], "stack": "age", "color": COLORS[s]}
                                          for s in vd.SEVERITIES]}


async def _mttr(ctx, p):
    ready = await _ready(ctx, p)
    m = ready["mttr"] if ready else await vd._mttr(ctx.db, _w(ctx, p))
    return {"x": m["months"], "y_unit": "days",
            "series": [{"name": SEV_LABEL[s], "data": m[s], "color": COLORS[s]} for s in ("critical", "high", "medium")]}


async def _breakdown(ctx, p) -> dict:
    ready = await _ready(ctx, p)
    return ready if ready else await vd._breakdowns(ctx.db, _w(ctx, p))


async def _by_type(ctx, p):
    b = await _breakdown(ctx, p)
    return {"items": [{"name": r["type"].replace("_", " "), "value": r["open"], "href": f"/devices?device_type={r['type']}"}
                      for r in b["by_type"]]}


async def _by_source(ctx, p):
    b = await _breakdown(ctx, p)
    return {"items": [{"name": r["source"].replace("_", " "), "value": r["open"], "href": f"/vulns?source={r['source']}"}
                      for r in b["by_source"]]}


async def _top_vulns(ctx, p):
    rows = (await _breakdown(ctx, p))["top_vulns"][:p["limit"]]
    return {"columns": ["Vulnerability", "CVSS", "KEV", "Devices"],
            "rows": [[f"{v['cve_id'] + ' ' if v['cve_id'] else ''}{v['title'][:80]}", v["cvss"], "KEV" if v["kev"] else "",
                      v["devices"]] for v in rows],
            "hrefs": [f"/vulns/{v['id']}" for v in rows]}


async def _top_devices(ctx, p):
    rows = (await _breakdown(ctx, p))["top_devices"][:p["limit"]]
    return {"columns": ["Device", "Grade", "Score", "Open", "KEV"],
            "rows": [[d["hostname"], d["grade"], round(d["score"]) if d["score"] is not None else None, d["open"], d["kev"]]
                     for d in rows],
            "hrefs": [f"/devices/{d['id']}" for d in rows]}


FILTERS = (SOURCE, DTYPE)
C = "Vulnerabilities"
metric(Metric("vuln.kpi", "Vulnerability number", C, "value",
              (Param("measure", "Number", MEASURES, labels=MEASURE_LABEL), SEVERITY, KEV, *FILTERS), _kpi,
              "One headline number: open, critical, KEV, past SLA, new or fixed this week, and more."))
metric(Metric("vuln.trend", "Open findings over time", C, "series",
              (RANGE, SEVERITY, KEV, Param("show_kev", "Add a KEV line", default=True), *FILTERS), _trend,
              "Daily open findings by severity, rebuilt from finding dates."))
metric(Metric("vuln.flow", "New vs fixed per day", C, "series", (RANGE, SEVERITY, KEV, *FILTERS), _flow))
metric(Metric("vuln.aging", "Age of open findings", C, "series", (SEVERITY, KEV, *FILTERS), _aging,
              "Open findings by how long they have been open."))
metric(Metric("vuln.mttr", "Mean days to remediate", C, "series", (SEVERITY, KEV, *FILTERS), _mttr))
metric(Metric("vuln.by_device_type", "Open findings by device type", C, "parts", (SEVERITY, KEV, SOURCE), _by_type))
metric(Metric("vuln.by_source", "Open findings by source", C, "parts", (SEVERITY, KEV, DTYPE), _by_source))
metric(Metric("vuln.top_vulns", "Most widespread vulnerabilities", C, "table", (LIMIT, SEVERITY, KEV, *FILTERS), _top_vulns))
metric(Metric("vuln.top_devices", "Riskiest devices", C, "table", (LIMIT, SEVERITY, KEV, *FILTERS), _top_devices))
