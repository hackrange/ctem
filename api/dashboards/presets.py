"""Stock widgets (ready-made, drag onto a dashboard) and starter dashboards built from them.

A preset is an ordinary widget: a catalog metric, a chart type, options and style. Nothing here bypasses the
catalog; every widget is cleaned by clean_widget and computed for the viewer like any other."""
from __future__ import annotations

from api.dashboards import catalog as cat


def _p(group, title, metric, viz, params=None, w=3, h=2, style=None):
    return {"group": group, "title": title, "metric": metric, "viz": viz, "params": params or {}, "style": style or {},
            "w": w, "h": h}


RISK, REM, ENV, ASSET, COVER, VULN, OPS = ("Risk overview", "Remediation", "Environment", "Asset inventory",
                                          "Coverage and tagging", "Vulnerability trends", "Operations")
TPRM = "Third-party risk"
_SPAN = (("q1", "Jan 1 to Mar 31"), ("q2", "Apr 1 to Jun 30"), ("q3", "Jul 1 to Sep 30"), ("q4", "Oct 1 to Dec 31"))
RED = {"color": "red", "warn_at": 1, "bad_at": 1}
PRESETS: dict[str, dict] = {
    # Risk overview
    "risk_gauge": _p(RISK, "Risk score", "risk.score", "gauge", w=4, h=4),
    "open_kpi": _p(RISK, "Open vulnerabilities", "vuln.kpi", "kpi", {"measure": "open"}),
    "critical_kpi": _p(RISK, "Critical findings", "vuln.kpi", "kpi", {"measure": "critical"}, style={"color": "red"}),
    "kev_kpi": _p(RISK, "Known exploited (KEV)", "vuln.kpi", "kpi", {"measure": "kev"}, style={"color": "red"}),
    "assets_kpi": _p(RISK, "Active assets", "assets.count", "kpi", {"seen": "active_30d"}),
    "vulns_vs_risk": _p(RISK, "Vulnerabilities vs risk score over time", "risk.vulns_vs_risk", "bar",
                        {"range": "90d", "bucket": "week", "split": "cloud", "with_risk": True}, w=8, h=4),
    "assets_by_sev": _p(RISK, "Assets over time by vulnerability severity", "risk.assets_by_severity", "area",
                        {"range": "90d", "bucket": "day"}, w=12, h=4, style={"opacity": 70}),
    "top_split": _p(RISK, "Top vulnerabilities, cloud vs on-prem", "risk.top_vulns_split", "table", {"limit": 5}, w=12, h=4),
    "vuln_map": _p(RISK, "Vulnerability risk map", "risk.vuln_scatter", "bubble", {"limit": 200}, w=6, h=5, style={"opacity": 60}),
    # Remediation
    "remediated_gauge": _p(REM, "Remediated vulnerabilities", "risk.remediated_pct", "gauge", w=4, h=4, style={"color": "green"}),
    "mttr_kpi": _p(REM, "Mean time to remediate", "risk.mttr", "kpi", {"days": "30"}),
    "new_vs_fixed": _p(REM, "New and remediated vs risk score", "risk.new_vs_fixed", "bar",
                       {"range": "90d", "bucket": "week", "with_risk": True}, w=8, h=4),
    **{f"mttr_{q}": _p(REM, f"MTTR {q.upper()} ({span})", "risk.mttr_quarter", "kpi", {"quarter": q}) for q, span in _SPAN},
    # Third-party risk (FairTPRM)
    **{f"t1_score_{q}": _p(TPRM, f"Tier 1 vendor score {q.upper()} ({span})", "tprm.score_quarter", "kpi", {"quarter": q, "tier": "tier1"})
       for q, span in _SPAN},
    "mttr_split": _p(REM, "Mean time to remediate, cloud vs on-prem", "risk.mttr_split", "line", {"bucket": "month"}, w=6, h=4),
    "mttr_sev": _p(REM, "Mean time to remediate by severity", "vuln.mttr", "line", w=6, h=4),
    "aging": _p(REM, "Age of open findings", "vuln.aging", "stacked", w=6, h=4),
    # Environment and accepted risk
    "assets_over_time": _p(ENV, "Cloud vs on-prem assets over time", "assets.over_time", "area", {"range": "90d", "bucket": "week"},
                           w=12, h=4, style={"opacity": 55}),
    "assets_vs_risk": _p(ENV, "Assets vs risk score over time", "assets.over_time", "bar",
                         {"range": "90d", "bucket": "week", "with_risk": True}, w=12, h=4),
    "accepted_gauge": _p(ENV, "Accepted risk", "risk.accepted", "gauge", w=4, h=4, style={"color": "orange"}),
    "accepted_trend": _p(ENV, "Accepted vulnerabilities vs accepted risk", "risk.accepted_trend", "bar",
                         {"range": "90d", "bucket": "week"}, w=8, h=4),
    # Asset inventory
    "servers_kpi": _p(ASSET, "Active servers", "assets.count", "kpi", {"device_type": "server", "seen": "active_30d"}),
    "compute_kpi": _p(ASSET, "Active compute assets", "assets.count", "kpi", {"device_type": "compute", "seen": "active_30d"}),
    "workstations_kpi": _p(ASSET, "Active workstations", "assets.count", "kpi", {"device_type": "workstation", "seen": "active_30d"}),
    "os_families": _p(ASSET, "Operating system families", "assets.by_os", "bar", {"seen": "active_30d"}, w=6, h=4),
    "asset_class": _p(ASSET, "Asset class", "devices.by_type", "bar", w=6, h=4),
    "new_assets": _p(ASSET, "Newly discovered assets", "assets.new", "kpi", {"days": "30"}),
    "obsolete_gauge": _p(ASSET, "Assets running obsolete software", "assets.obsolete_os", "gauge", w=3, h=3, style={"color": "orange"}),
    "critical_assets": _p(ASSET, "Assets with critical vulnerabilities", "assets.critical", "kpi", style={"color": "red"}),
    "expired_certs": _p(ASSET, "Assets with expired certificates", "assets.certificates", "kpi", {"kind": "expired"}),
    "asset_map": _p(ASSET, "Asset risk map", "assets.risk_scatter", "bubble", {"limit": 250}, w=6, h=5, style={"opacity": 60}),
    # Coverage and tagging
    "win_ws": _p(COVER, "Windows workstations", "assets.count", "kpi", {"device_type": "workstation", "os_family": "windows", "seen": "active_30d"}),
    "win_srv": _p(COVER, "Windows servers", "assets.count", "kpi", {"device_type": "server", "os_family": "windows", "seen": "active_30d"}),
    "linux_srv": _p(COVER, "Linux servers", "assets.count", "kpi", {"device_type": "server", "os_family": "linux", "seen": "active_30d"}),
    "win_ws_noscan": _p(COVER, "Windows workstations without a scanner", "assets.count", "kpi",
                        {"device_type": "workstation", "os_family": "windows", "missing": "scanner", "seen": "active_30d"}, style=RED),
    "win_srv_noscan": _p(COVER, "Windows servers without a scanner", "assets.count", "kpi",
                         {"device_type": "server", "os_family": "windows", "missing": "scanner", "seen": "active_30d"}, style=RED),
    "linux_srv_noscan": _p(COVER, "Linux servers without a scanner", "assets.count", "kpi",
                           {"device_type": "server", "os_family": "linux", "missing": "scanner", "seen": "active_30d"}, style=RED),
    "compute_noedr": _p(COVER, "Workstations and servers without EDR", "assets.count", "kpi",
                        {"device_type": "compute", "missing": "edr", "seen": "active_30d"}, style=RED),
    "coverage_trend": _p(COVER, "EDR and scanner coverage over time", "coverage.trend", "line", {"range": "90d", "bucket": "day"}, w=6, h=4),
    "edr_coverage": _p(COVER, "EDR coverage", "devices.edr_coverage", "gauge", w=3, h=3),
    "tag_crit": _p(COVER, "Assets tagged by criticality", "coverage.tagged", "donut", {"by": "criticality"}, w=6, h=4),
    "tag_owner": _p(COVER, "Assets tagged by owner", "coverage.tagged", "donut", {"by": "owner"}, w=6, h=4),
    "tag_location": _p(COVER, "Assets tagged by location", "coverage.tagged", "donut", {"by": "location"}, w=6, h=4),
    "tag_app": _p(COVER, "Assets tagged with an application", "coverage.tagged", "donut", {"by": "application"}, w=6, h=4),
    # Vulnerability trends
    "open_trend": _p(VULN, "Open findings over time", "vuln.trend", "area", {"range": "90d"}, w=12, h=4, style={"opacity": 60}),
    "flow": _p(VULN, "New vs fixed per day", "vuln.flow", "bar", {"range": "30d"}, w=6, h=4),
    "kev_trend": _p(VULN, "Known exploited findings over time", "vuln.trend", "line", {"range": "180d", "kev_only": True}, w=6, h=4),
    "by_source": _p(VULN, "Open findings by source", "vuln.by_source", "pie", w=4, h=4),
    "top_vulns": _p(VULN, "Most widespread vulnerabilities", "vuln.top_vulns", "table", {"limit": 10}, w=6, h=5),
    "riskiest": _p(VULN, "Riskiest devices", "vuln.top_devices", "table", {"limit": 10}, w=6, h=5),
    "past_sla": _p(VULN, "Past SLA", "vuln.kpi", "kpi", {"measure": "past_sla"}, style={"color": "orange", "warn_at": 1, "bad_at": 100}),
    # Operations
    "stale_ad": _p(OPS, "Stale AD computers (21+ days)", "directory.stale_computers", "kpi", {"days": 21}),
    "checks": _p(OPS, "Control checks by result", "grc.check_status", "donut", w=4, h=4),
    "alerts": _p(OPS, "Alerts over time", "threats.over_time", "stacked", {"range": "30d"}, w=8, h=4),
}

TEMPLATES = (
    {"key": "risk_overview", "name": "Risk overview", "theme": "default",
     "description": "Your vulnerability risk across cloud and on-prem: score, trend, severity mix and the top vulnerabilities.",
     "rows": [["open_kpi", "critical_kpi", "kev_kpi", "assets_kpi"], ["risk_gauge", "vulns_vs_risk"], ["assets_by_sev"], ["top_split"]]},
    {"key": "remediation", "name": "Remediation progress", "theme": "forest",
     "description": "How well remediation is reducing risk: share fixed, new vs fixed, and mean time to remediate.",
     "rows": [["remediated_gauge", "new_vs_fixed"], ["mttr_kpi", "past_sla"], ["mttr_split", "mttr_sev"]]},
    {"key": "mttr_quarters", "name": "Mean time to remediate by quarter", "theme": "forest",
     "description": "One card per calendar quarter of this year: average days from detection to fix, and the change "
                    "from the quarter before. Then the monthly trend by severity.",
     "rows": [["mttr_q1", "mttr_q2", "mttr_q3", "mttr_q4"], ["mttr_sev", "mttr_split"]]},
    {"key": "tprm_quarters", "name": "Vendor security score by quarter", "theme": "slate",
     "description": "The average security score percentage of tier 1 vendors at the end of each calendar quarter of this "
                    "year, with the change from the quarter before. Edit a card to pick another tier or one vendor.",
     "rows": [["t1_score_q1", "t1_score_q2", "t1_score_q3", "t1_score_q4"]]},
    {"key": "environment", "name": "Environment trends", "theme": "ocean",
     "description": "Your estate over time, cloud vs on-prem, against the risk score, and how much risk is accepted.",
     "rows": [["assets_over_time"], ["assets_vs_risk"], ["accepted_gauge", "accepted_trend"]]},
    {"key": "coverage", "name": "Asset coverage", "theme": "slate",
     "description": "What your scanners and EDR can see, by OS and type, and how well assets are tagged.",
     "rows": [["win_ws", "win_srv", "linux_srv", "new_assets"], ["win_ws_noscan", "win_srv_noscan", "linux_srv_noscan", "compute_noedr"],
              ["coverage_trend", "edr_coverage", "obsolete_gauge"], ["tag_crit", "tag_owner"], ["tag_location", "tag_app"]]},
    {"key": "inventory", "name": "Asset inventory", "theme": "violet",
     "description": "Active assets, servers and workstations, OS families and asset classes, and where the risk sits.",
     "rows": [["assets_kpi", "servers_kpi", "compute_kpi", "workstations_kpi"], ["os_families", "asset_class"],
              ["critical_assets", "expired_certs", "obsolete_gauge"], ["asset_map", "vuln_map"]]},
    {"key": "vuln_trends", "name": "Vulnerability trends", "theme": "neon",
     "description": "Open findings over time, new vs fixed, known-exploited trend, sources and the worst offenders.",
     "rows": [["open_kpi", "critical_kpi", "kev_kpi", "past_sla"], ["open_trend"], ["flow", "kev_trend"], ["top_vulns", "riskiest"]]},
)


def widget(key: str, x: int = 0, y: int = 0) -> dict | None:
    p = PRESETS.get(key)
    if p is None:
        return None
    return cat.clean_widget({**{k: v for k, v in p.items() if k != "group"}, "x": x, "y": y})


def pack(keys_rows: list[list[str]], ctx=None) -> list[dict]:
    """Lay rows of presets out left to right; a row that runs past 12 columns wraps. Widgets the viewer
    can't see are skipped."""
    out, y = [], 0
    for row in keys_rows:
        x, tallest = 0, 0
        for k in row:
            w = widget(k)
            if not w or (ctx is not None and not cat.allowed(cat.REGISTRY[w["metric"]], ctx)):
                continue
            if x + w["w"] > cat.GRID_COLS:
                x, y, tallest = 0, y + tallest, 0
            w.update(x=x, y=y)
            out.append(w)
            x += w["w"]
            tallest = max(tallest, w["h"])
        if row and x and x < cat.GRID_COLS and out:   # stretch the last widget of a short row to fill it
            last = out[-1]
            if last["y"] == y:
                last["w"] = cat.GRID_COLS - last["x"]
        y += tallest
    return out


def for_viewer(ctx) -> dict:
    presets = []
    for k, p in PRESETS.items():
        m = cat.REGISTRY.get(p["metric"])
        if m and cat.allowed(m, ctx):
            presets.append({"key": k, **p, "shape": m.shape})
    return {"presets": presets,
            "templates": [{"key": t["key"], "name": t["name"], "description": t["description"], "theme": t["theme"],
                           "widgets": len(pack(t["rows"], ctx))} for t in TEMPLATES]}
