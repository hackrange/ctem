"""Asset widgets: counts by type and OS family with what's missing (no EDR, no vulnerability scanner), OS families,
tag coverage (criticality, owner, location...), new assets, obsolete OS, certificate problems, assets over time
(cloud vs on-prem, optionally with the risk score), EDR and scanner coverage over time, and a risk scatter.
Cards link to the device list with the same filters."""
from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlencode

from sqlalchemy import func, or_, select

from api.dashboards import fleet
from api.dashboards.catalog import Metric, Param, metric
from api.models.device import Device, DeviceTag, DeviceType, RiskGrade
from api.models.vuln import Finding, FindingStatus, Vulnerability

OPEN = (FindingStatus.open, FindingStatus.in_progress)
TYPES = ("any", "compute", *DeviceType.__members__)
TYPE_LABEL = {"any": "All types", "compute": "Workstations and servers", "network_device": "Network devices",
              "workstation": "Workstations", "server": "Servers", "unknown": "Other devices",
              "code_repository": "Code (SAST)", "website": "Web applications (DAST)", "cloud_instance": "Cloud instances"}
MISSING = ("none", "edr", "scanner", "either")
MISSING_LABEL = {"none": "Everything", "edr": "Without EDR", "scanner": "Without a vulnerability scanner",
                 "either": "Without EDR or a scanner"}
SEEN = Param("seen", "Which", ("active_30d", "any"), labels={"active_30d": "Seen in the last 30 days", "any": "All, even stale"})
DTYPE = Param("device_type", "Device type", TYPES, labels=TYPE_LABEL)
OSF = Param("os_family", "OS family", ("any", *fleet.OS_FAMILIES), labels={"any": "Any OS", **fleet.OS_LABEL})
RANGE = Param("range", "Range", tuple(fleet.RANGE_DAYS), default="90d", labels=fleet.RANGE_LABEL)
BUCKET = Param("bucket", "Group by", fleet.BUCKETS, labels=fleet.BUCKET_LABEL)
GRADE_COLOR = {"A": "--severity-info", "B": "--severity-low", "C": "--severity-medium", "D": "--severity-high", "F": "--severity-critical"}
COVER = ("criticality", "owner", "executive_owner", "technical_owner", "application_owner", "application", "environment",
         "location", "business_unit")
COVER_LABEL = {"criticality": "Criticality", "owner": "Any owner", "executive_owner": "Executive owner",
               "technical_owner": "Technical owner", "application_owner": "Application owner", "application": "Application",
               "environment": "Environment", "location": "Location", "business_unit": "Business unit"}
CRIT_COLOR = {"very high": "--severity-critical", "high": "--severity-high", "medium": "--severity-medium",
              "low": "--severity-low", "very low": "--severity-info"}
OBSOLETE = ("%obsolete%", "%end of life%", "%end-of-life%", "%unsupported%")
CERT = {"expired": ("%certificate%expired%", "%expired%certificate%"), "self_signed": ("%self-signed%", "%self signed%"),
        "weak": ("%certificate%weak%", "%weak%certificate%", "%certificate%sha1%", "%certificate%md5%"),
        "any": ("%certificate%",)}


def where(ctx, p) -> list:
    w = fleet.scoped(ctx)
    t = p.get("device_type", "any")
    if t == "compute":
        w.append(Device.device_type.in_(fleet.COMPUTE))
    elif t in DeviceType.__members__:
        w.append(Device.device_type == DeviceType[t])
    if p.get("os_family", "any") in fleet.OS_FAMILIES:
        w.append(fleet.os_family() == p["os_family"])
    m = p.get("missing", "none")
    if m == "edr":
        w.append(~fleet.has_edr())
    elif m == "scanner":
        w.append(~fleet.has_scanner())
    elif m == "either":
        w.append(or_(~fleet.has_edr(), ~fleet.has_scanner()))
    if p.get("seen") == "active_30d":
        w.append(fleet.active(30))
    return w


def href(p, **extra) -> str:
    q = {}
    t = p.get("device_type", "any")
    if t == "compute":
        q["compute"] = "1"
    elif t != "any":
        q["device_type"] = t
    for k in ("os_family", "missing"):
        if p.get(k) not in (None, "any", "none"):
            q[k] = p[k]
    if p.get("seen") == "active_30d":
        q["active_days"] = "30"
    q.update({k: str(v) for k, v in extra.items()})
    return "/devices" + ("?" + urlencode(q) if q else "")


async def _count(ctx, p):
    n = (await ctx.db.execute(select(func.count()).select_from(Device).where(*where(ctx, p)))).scalar_one()
    bits = [TYPE_LABEL.get(p["device_type"], p["device_type"].replace("_", " ")) if p["device_type"] != "any" else "Devices"]
    if p["os_family"] != "any":
        bits.insert(0, fleet.OS_LABEL[p["os_family"]])
    if p["os_family"] != "any" and len(bits) == 2:
        bits[1] = bits[1].lower()
    note = " ".join(bits) + ("" if p["missing"] == "none" else " " + MISSING_LABEL[p["missing"]].replace("Without", "without"))
    return {"value": n, "href": href(p), "note": note + (", seen in 30 days" if p["seen"] == "active_30d" else "")}


async def _by_os(ctx, p):
    fam = fleet.os_family()
    rows = (await ctx.db.execute(select(fam, func.count()).where(*where(ctx, {**p, "os_family": "any"}))
                                 .group_by(fam).order_by(func.count().desc()))).all()
    return {"items": [{"name": fleet.OS_LABEL.get(f, f), "value": n, "href": href({**p, "os_family": f})} for f, n in rows]}


def _role_cond(keys):
    from api.core import tag_roles
    from api.models.tag import Tag
    from api.rules.apply import _like
    conds = []
    for r in tag_roles.current():
        if r.key in keys:
            for kind, v in r.rules:
                conds.append(func.lower(Tag.name) == v if kind == "exact" else func.lower(Tag.name).like(_like(v) + "%", escape="\\"))
    if not conds:
        return None
    return Device.id.in_(select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(or_(*conds)))


async def _coverage(ctx, p):
    from api.core import tag_roles
    await tag_roles.ensure(ctx.db)
    w = where(ctx, {"seen": p["seen"]})
    total = (await ctx.db.execute(select(func.count()).select_from(Device).where(*w))).scalar_one()
    by = p["by"]
    if by == "criticality":
        crit = func.lower(func.coalesce(func.nullif(func.trim(Device.criticality), ""), "not set"))
        rows = (await ctx.db.execute(select(crit, func.count()).where(*w).group_by(crit).order_by(func.count().desc()))).all()
        items = [{"name": c.title() if c != "not set" else "Not tagged", "value": n,
                  "color": CRIT_COLOR.get(c, "--border" if c == "not set" else None)} for c, n in rows]
        tagged = sum(n for c, n in rows if c != "not set")
    else:
        cond = _role_cond(tag_roles.OWNER_ROLES if by == "owner" else (by,))
        tagged = 0 if cond is None else (await ctx.db.execute(select(func.count()).select_from(Device).where(*w, cond))).scalar_one()
        items = [{"name": "Tagged", "value": tagged, "color": "--accent"},
                 {"name": "Not tagged", "value": total - tagged, "color": "--border"}]
    pct = 100 * tagged / total if total else 0
    return {"items": items, "center": {"value": total, "label": "assets"},
            "headline": f"{pct:.1f}% of {total:,} assets are tagged by {COVER_LABEL[by].lower()}"}


async def _new(ctx, p):
    days = int(p["days"])
    cut = fleet.now().replace(tzinfo=None) - timedelta(days=days)
    w = [*fleet.scoped(ctx), Device.created_at >= cut]
    n = (await ctx.db.execute(select(func.count()).select_from(Device).where(*w))).scalar_one()
    return {"value": n, "href": f"/devices?new_days={days}", "note": f"Assets CTEM first saw in the last {days} days"}


def _with_vuln(patterns) -> object:
    vids = select(Vulnerability.id).where(or_(*(Vulnerability.title.ilike(x) for x in patterns)))
    return Device.id.in_(select(Finding.device_id).where(Finding.status.in_(OPEN), Finding.vuln_id.in_(vids)))


async def _obsolete(ctx, p):
    w = where(ctx, {"seen": "active_30d"})
    total, bad = (await ctx.db.execute(select(func.count(), func.count().filter(_with_vuln(OBSOLETE)))
                                       .select_from(Device).where(*w))).one()
    return {"value": round(100 * bad / total, 1) if total else None, "unit": "%", "max": 100, "href": "/vulns?q=obsolete",
            "note": f"{bad:,} of {total:,} active assets run obsolete or unsupported software"}


async def _critical(ctx, p):
    crit = select(Vulnerability.id).where(Vulnerability.cvss_base >= 9.0)
    n = (await ctx.db.execute(select(func.count(func.distinct(Finding.device_id))).where(
        Finding.status.in_(OPEN), Finding.vuln_id.in_(crit), *([Finding.device_id.in_(select(Device.id).where(ctx.scope))]
                                                               if ctx.scope is not None else [])))).scalar_one()
    return {"value": n, "href": "/vulns?min_cvss=9", "note": "Assets with critical vulnerabilities"}


async def _certs(ctx, p):
    n = (await ctx.db.execute(select(func.count()).select_from(Device).where(*fleet.scoped(ctx), _with_vuln(CERT[p["kind"]])))).scalar_one()
    label = {"expired": "expired", "self_signed": "self-signed", "weak": "weak", "any": "problem"}[p["kind"]]
    return {"value": n, "href": "/vulns?q=certificate", "note": f"Assets with {label} certificates"}


async def _over_time(ctx, p):
    days, unit = fleet.RANGE_DAYS[p["range"]], p["bucket"]
    day = func.date(Device.created_at)   # works in Postgres and SQLite
    is_cloud = Device.id.in_(fleet.cloud_ids())
    rows = (await ctx.db.execute(select(day, func.count().filter(is_cloud), func.count().filter(~is_cloud))
                                 .where(*fleet.scoped(ctx)).group_by(day))).all()
    today = fleet.now().date()
    start = today - timedelta(days=days - 1)
    cl = on = 0
    per = {}
    from datetime import date
    for d, c, o in sorted((date.fromisoformat(str(d)[:10]), c, o) for d, c, o in rows if d is not None):
        if d < start:
            cl, on = cl + c, on + o
        else:
            per[d] = (c, o)
    x, a, b = [], [], []
    for i in range(days):
        d = start + timedelta(days=i)
        c, o = per.get(d, (0, 0))
        cl, on = cl + c, on + o
        x.append(d.isoformat())
        a.append(cl)
        b.append(on)
    labels, (a2, b2) = fleet.resample(x, [a, b], unit, ["last", "last"])
    series = [{"name": "On-prem", "data": b2, "stack": "a", "color": "--severity-info"},
              {"name": "Cloud", "data": a2, "stack": "a", "color": "--accent"}]
    if p.get("with_risk") and ctx.scope is None:
        from api.dashboards.m_risk import _risk_line
        line = await _risk_line(ctx, x, unit)
        if line:
            series.append(line)
    return {"x": labels, "series": series, "y2_unit": "risk", "headline": fleet.change([i + j for i, j in zip(a, b)], "assets"),
            "note": "Counts assets by when CTEM first saw them; retired assets drop out of earlier points."}


async def _coverage_trend(ctx, p):
    if (e := fleet.fleet_only(ctx)):
        return e
    x, s = await fleet.snaps(ctx.db, ["cov_eligible", "cov_edr", "cov_scanner"], fleet.RANGE_DAYS[p["range"]])
    pct = lambda k: [round(100 * v / e, 1) if v is not None and e else None for v, e in zip(s[k], s["cov_eligible"])]  # noqa: E731
    labels, (edr, scan, elig) = fleet.resample(x, [pct("cov_edr"), pct("cov_scanner"), s["cov_eligible"]], p["bucket"], ["avg", "avg", "last"])
    return {"x": labels, "y_unit": "%", "series": [{"name": "With EDR", "data": edr, "color": "--accent"},
                                                     {"name": "With a scanner", "data": scan, "color": "--severity-info"}],
            "note": "Active workstations and servers. Builds from a daily snapshot." if sum(v is not None for v in edr) < 3 else None}


async def _scatter(ctx, p):
    w = [*fleet.scoped(ctx), Device.risk_score.is_not(None), Device.open_findings > 0]
    rows = (await ctx.db.execute(select(Device.id, Device.hostname, Device.risk_grade, Device.risk_score, Device.open_findings,
                                        Device.kev_findings).where(*w).order_by(Device.risk_score.desc()).limit(p["limit"]))).all()
    from api.routes import device_query as dq
    groups: dict = {}
    for i, h, g, s, o, k in rows:
        key = g.value if g else "?"
        groups.setdefault(key, []).append([o, round(s, 1), max(k, 1), dq.short_name(h), f"/devices/{i}"])
    order = [g.value for g in RiskGrade]
    return {"x_label": "Open findings", "y_label": "Risk score", "size_label": "KEV findings",
            "groups": [{"name": f"Grade {g}", "color": GRADE_COLOR.get(g), "points": groups[g]}
                       for g in sorted(groups, key=lambda g: order.index(g) if g in order else 99)]}


A, CV = "Assets", "Coverage and tagging"
metric(Metric("assets.count", "Asset count", A, "value", (DTYPE, OSF, Param("missing", "Show", MISSING, labels=MISSING_LABEL), SEEN),
              _count, "How many assets of a type and OS family, optionally only those without EDR or a scanner."))
metric(Metric("assets.by_os", "Operating system families", A, "parts", (DTYPE, SEEN), _by_os))
metric(Metric("assets.new", "Newly discovered assets", A, "value",
              (Param("days", "In the last", ("30", "7", "90"), labels={"7": "7 days", "30": "30 days", "90": "90 days"}),), _new))
metric(Metric("assets.obsolete_os", "Assets running obsolete software", A, "value", (), _obsolete,
              "Share of active assets with an open finding for obsolete, end-of-life or unsupported software."))
metric(Metric("assets.critical", "Assets with critical vulnerabilities", A, "value", (), _critical))
metric(Metric("assets.certificates", "Assets with certificate problems", A, "value",
              (Param("kind", "Problem", tuple(CERT), labels={"expired": "Expired", "self_signed": "Self-signed", "weak": "Weak", "any": "Any"}),),
              _certs, "From scanner findings about TLS/SSL certificates."))
metric(Metric("assets.over_time", "Assets over time, cloud vs on-prem", A, "series",
              (RANGE, BUCKET, Param("with_risk", "Add the risk score line", default=False)), _over_time))
metric(Metric("assets.risk_scatter", "Asset risk map", A, "points", (Param("limit", "Assets", low=25, high=500, default=250),),
              _scatter, "Each dot is a device: open findings across, risk score up, size is KEV findings."))
metric(Metric("coverage.tagged", "Assets tagged by", CV, "parts", (Param("by", "Tagged by", COVER, labels=COVER_LABEL), SEEN),
              _coverage, "How many assets carry a criticality, owner, application, location... tag. Uses Admin > Tag mapping."))
metric(Metric("coverage.trend", "EDR and scanner coverage over time", CV, "series", (RANGE, BUCKET), _coverage_trend, filterable=False))
