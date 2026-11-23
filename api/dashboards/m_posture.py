"""Posture widgets: domain scorecards (count, average and maximum age per issue), control check compliance, and
asset reporting coverage. Every number honors the viewer's access and the widget and dashboard filters (owner,
application, environment...), which narrow the devices through ctx.scope."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, func, or_, select

from api.core import vuln_dashboard as vd
from api.core.device_scope_exempt import in_scope_findings
from api.dashboards import fleet
from api.dashboards.catalog import Metric, Param, metric
from api.models.device import Device, DeviceTag, DeviceType, NON_HOST_TYPES
from api.models.vuln import Finding, FindingStatus, Vulnerability

OPEN = (FindingStatus.open, FindingStatus.in_progress)
APPS = (DeviceType.code_repository, DeviceType.website)
AREAS = ("vulnerabilities", "endpoint", "identity", "code", "web", "ownership")
AREA_LABEL = {"vulnerabilities": "Servers and vulnerabilities", "endpoint": "Endpoint protection",
              "identity": "Identity (directory)", "code": "Developer security (code)", "web": "Web applications",
              "ownership": "Ownership and coverage"}


def days_since(db, col):
    """Days from a timestamp column until now, in SQL (Postgres and SQLite)."""
    if db.bind.dialect.name == "sqlite":
        return func.julianday("now") - func.julianday(col)
    return func.extract("epoch", func.now() - col) / 86400.0


def _fmt(d) -> str | None:
    return None if d is None else f"{int(round(float(d)))}d"


def _tone(n: int, bad: str) -> dict:
    """A count cell, colored when it needs attention (bad: critical or high)."""
    return {"v": n, "tone": bad if n else "low"}


async def _findings(ctx, *cond, devices: bool = False) -> tuple[int, float | None, float | None]:
    """Open findings (or the distinct assets they are on): count, average and maximum age in days."""
    age = days_since(ctx.db, Finding.first_detected)
    n = func.count(func.distinct(Finding.device_id)) if devices else func.count()
    q = (select(n, func.avg(age), func.max(age)).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
         .where(Finding.status.in_(OPEN), in_scope_findings(), *vd.scoped(ctx.scope), *cond))
    c, a, m = (await ctx.db.execute(q)).one()
    return c or 0, a, m


async def _devices(ctx, *cond, since=None) -> tuple[int, float | None, float | None]:
    """Assets matching: count, and the average and maximum days since `since` (a Device column)."""
    cols = [func.count()]
    if since is not None:
        age = days_since(ctx.db, since)
        cols += [func.avg(age), func.max(age)]
    r = (await ctx.db.execute(select(*cols).select_from(Device).where(*fleet.scoped(ctx), *cond))).one()
    return (r[0] or 0, r[1], r[2]) if since is not None else (r[0] or 0, None, None)


def _past_sla():
    from api.core.sla import current
    sev = vd._sev()
    cut = fleet.now()
    return or_(*[and_(sev == s, Finding.first_detected < cut - timedelta(days=d)) for s, d in current().items()])


def _without_role(role_tags: list[str]):
    """Assets with none of these tags."""
    from api.models.tag import Tag
    has = select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(Tag.name.in_(role_tags or ["__none__"]))
    return Device.id.not_in(has)


async def _role_tags(db, key: str) -> list[str]:
    from api.core import tag_roles
    roles = await tag_roles.ensure(db)
    return [o["tag"] for o in (await tag_roles.options(db, roles)).get(key, [])]


async def _rows(ctx, area: str) -> list[tuple]:
    """(label, source, (count, avg, max), tone, href) per issue in an area."""
    from api.core import sla
    await sla.load(ctx.db)
    hosts = Device.device_type.not_in(NON_HOST_TYPES)
    compute = Device.device_type.in_(fleet.COMPUTE)
    active = fleet.active(30)
    crit_high, kev = Vulnerability.cvss_base >= 7.0, Vulnerability.is_kev == True  # noqa: E712
    out = []
    if area == "vulnerabilities":
        infra = Finding.domain == "infra"
        out.append(("Critical/high vulnerabilities", "Vulnerability scanners", await _findings(ctx, infra, crit_high), "critical", "/vulns?type=infra&min_cvss=7"))
        out.append(("Known exploited (KEV)", "Scanners + CISA KEV", await _findings(ctx, infra, kev), "critical", "/vulns?type=infra&is_kev=true"))
        out.append(("Vulnerabilities past SLA", "Change SLAs", await _findings(ctx, infra, _past_sla()), "high", "/vulns?type=infra"))
        from api.dashboards.m_assets import OBSOLETE
        eol = or_(*(Vulnerability.title.ilike(x) for x in OBSOLETE))
        out.append(("End-of-life software (assets)", "Vulnerability scanners", await _findings(ctx, infra, eol, devices=True), "high", "/vulns?q=obsolete"))
        out.append(("Active hosts no scanner covers", "Asset inventory", await _devices(ctx, compute, active, ~fleet.has_scanner(), since=Device.created_at),
                    "medium", "/devices?missing=scanner&active_days=30"))
    elif area == "endpoint":
        out.append(("Missing EDR agent", "EDR", await _devices(ctx, compute, active, ~fleet.has_edr(), since=Device.created_at), "critical",
                    "/devices?missing=edr&active_days=30"))
        quiet = and_(Device.edr_last_seen.is_not(None), Device.edr_last_seen < fleet.now() - timedelta(days=7))
        out.append(("EDR agent not reporting (7+ days)", "EDR", await _devices(ctx, compute, active, quiet, since=Device.edr_last_seen), "high", "/devices?active_days=30"))
        out.append(("Contained hosts", "EDR", await _devices(ctx, Device.edr_contained.is_(True)), "medium", "/devices?status=contained"))
        if ctx.threats and ctx.scope is None:   # alerts are fleet-wide
            from api.dashboards.m_other import _alerts
            al = [a for a in await _alerts(ctx, {"range": "90d", "open_only": True})]
            ages = [x for x in ((fleet.now() - _parse(a.get("detected_at"))).days for a in al if a.get("detected_at")) if x >= 0]
            out.append(("Open endpoint detections (90 days)", "EDR detections", (len(al), sum(ages) / len(ages) if ages else None, max(ages) if ages else None),
                        "critical", "/threats"))
    elif area == "identity":
        from api.dashboards.m_directory import stale_computers
        for days in (90, 45):
            out.append((f"AD computers with no logon in {days} days", "Directory (AD/LDAP)",
                        await _devices(ctx, *stale_computers(days), since=Device.ad_last_logon), "high" if days == 90 else "medium",
                        f"/devices?ad_stale_days={days}"))
        if ctx.scope is None:   # directory accounts aren't assets, so they're for fleet-wide viewers
            from api.dashboards.m_directory import stale_users
            from api.models.user import User
            age = days_since(ctx.db, User.ad_last_logon)
            r = (await ctx.db.execute(select(func.count(), func.avg(age), func.max(age)).where(*stale_users(90)))).one()
            out.append(("AD user accounts with no logon in 90 days", "Directory (AD/LDAP)", (r[0] or 0, r[1], r[2]), "high", "/directory/users"))
    elif area in ("code", "web"):
        dt = DeviceType.code_repository if area == "code" else DeviceType.website
        what = "Repositories" if area == "code" else "Web applications"
        dom = Finding.domain == area
        out.append((f"{what} in scope", "Code and web scanners", await _devices(ctx, Device.device_type == dt), "", f"/devices?asset={'repositories' if area == 'code' else 'sites'}"))
        out.append((f"{what} with open findings", "Code and web scanners", await _findings(ctx, dom, devices=True), "high",
                    f"/devices?asset={'repositories' if area == 'code' else 'sites'}"))
        out.append(("Critical/high findings", "Code and web scanners", await _findings(ctx, dom, crit_high), "critical", f"/vulns?type={area}&min_cvss=7"))
        if area == "code":
            secret = Vulnerability.source_vuln_id.like("credential:%")
            out.append(("Credentials found in code", "Secret scanning", await _findings(ctx, dom, secret), "critical", "/vulns?type=code&q=secret"))
        else:
            exposed = Finding.device_id.in_(select(Device.id).where(Device.is_internet_exposed.is_(True)))
            out.append(("Findings on internet-facing sites", "Web scanners", await _findings(ctx, dom, exposed), "high", "/vulns?type=web"))
        out.append(("Past SLA", "Change SLAs", await _findings(ctx, dom, _past_sla()), "high", f"/vulns?type={area}"))
    elif area == "ownership":
        for key, label in (("technical_owner", "Assets without a technical owner"), ("executive_owner", "Assets without an executive owner"),
                           ("application", "Assets not mapped to an application")):
            tags = await _role_tags(ctx.db, key)
            out.append((label, "Tag mapping", await _devices(ctx, active, _without_role(tags), since=Device.created_at), "high", "/devices"))
        stale = and_(Device.last_seen < fleet.now() - timedelta(days=30), ~active)
        out.append(("Not seen by any tool in 30 days", "Asset inventory", await _devices(ctx, stale, since=Device.last_seen), "medium", "/devices"))
    return out


def _parse(iso):
    from datetime import datetime, timezone
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return fleet.now()


async def _scorecard(ctx, p):
    rows = await _rows(ctx, p["area"])
    return {"columns": ["Metric", "Count", "Avg age", "Max age", "Source"],
            "rows": [[label, _tone(c, tone) if tone else c, _fmt(a), {"v": _fmt(m), "tone": "critical"} if m and m > 90 else _fmt(m), src]
                     for label, src, (c, a, m), tone, _ in rows],
            "hrefs": [h for *_, h in rows], "headline": AREA_LABEL[p["area"]]}


async def _compliance(ctx, p):
    from api.dashboards.m_other import _checks
    results = [r for _, _, r in await _checks(ctx)]
    ran = [r for r in results if r is not None and r.result in ("pass", "warning", "fail")]
    ok = sum(1 for r in ran if r.result == "pass" or (p["count"] == "passing_or_warning" and r.result == "warning"))
    return {"value": round(100 * ok / len(ran), 1) if ran else None, "unit": "%", "max": 100, "href": "/grc",
            "note": f"{ok} of {len(ran)} evaluated control checks {'passing' if p['count'] == 'passing' else 'passing or warning'}"}


async def _reporting(ctx, p):
    """Share of active workstations and servers a scanner, an EDR, or both report on."""
    tool = {"scanner": fleet.has_scanner(), "edr": fleet.has_edr(), "either": or_(fleet.has_scanner(), fleet.has_edr()),
            "both": and_(fleet.has_scanner(), fleet.has_edr())}[p["tool"]]
    base = [Device.device_type.in_(fleet.COMPUTE), fleet.active(30), *fleet.scoped(ctx)]
    total, good = (await ctx.db.execute(select(func.count(), func.count().filter(tool)).select_from(Device).where(*base))).one()
    word = {"scanner": "a vulnerability scanner", "edr": "an EDR", "either": "a scanner or an EDR", "both": "both a scanner and an EDR"}[p["tool"]]
    return {"value": round(100 * good / total, 1) if total else None, "unit": "%", "max": 100,
            "href": f"/devices?missing={'either' if p['tool'] in ('both', 'either') else p['tool']}&active_days=30",
            "note": f"{good:,} of {total:,} active hosts report to {word}"}


C = "Posture"
metric(Metric("posture.scorecard", "Domain scorecard", C, "table",
              (Param("area", "Area", AREAS, labels=AREA_LABEL),), _scorecard,
              "One area's issues as rows with Count, Avg age and Max age (days), like a compliance scorecard: "
              "servers and vulnerabilities, endpoint protection, identity, code, web apps, or ownership and coverage."))
metric(Metric("grc.compliance", "Control checks passing", C, "value",
              (Param("count", "Count as compliant", ("passing", "passing_or_warning"),
                     labels={"passing": "Passing only", "passing_or_warning": "Passing or warning"}),), _compliance,
              "Overall compliance: the share of evaluated CTEM control checks that pass.", needs="grc", filterable=False))
metric(Metric("assets.reporting", "Hosts reporting", C, "value",
              (Param("tool", "Reporting to", ("either", "scanner", "edr", "both"),
                     labels={"either": "A scanner or an EDR", "scanner": "A vulnerability scanner", "edr": "An EDR", "both": "Both"}),),
              _reporting, "Data coverage: the share of active workstations and servers a scanner, an EDR, or both report on."))
