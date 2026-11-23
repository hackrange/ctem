"""Work queue widgets: the highest-risk open findings with their owner, application, age and due date, and a
headline number with the average and oldest age, for Infrastructure, Code and Web apps."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from api.core import finding_age, vuln_dashboard as vd
from api.core.device_scope_exempt import in_scope_findings
from api.dashboards.catalog import Metric, Param, metric
from api.dashboards.m_posture import OPEN, days_since
from api.dashboards.m_vulns import KEV, LIMIT, SEVERITY, SOURCE, _sev_cond
from api.models.device import Device, DeviceTag
from api.models.vuln import Finding, Vulnerability

TYPE = Param("type", "Type", ("any", "infra", "code", "web"),
             labels={"any": "Infrastructure, Code and Web apps", "infra": "Infrastructure", "code": "Code", "web": "Web apps"})
SEV_TONE = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
MEASURES = ("count", "avg_age", "max_age")
MEASURE_LABEL = {"count": "How many (with average and oldest age)", "avg_age": "Average age (days)", "max_age": "Oldest (days)"}


def _w(ctx, p) -> list:
    w = [Finding.status.in_(OPEN), in_scope_findings(), *vd.scoped(ctx.scope)]
    if p.get("type", "any") != "any":
        w.append(Finding.domain == p["type"])
    from api.dashboards.m_vulns import _srcs
    if _srcs(p):
        w.append(Finding.source.in_(_srcs(p)))
    cond = _sev_cond(p.get("severity", "any"))
    if cond is not None:
        w.append(cond)
    if p.get("kev_only"):
        w.append(Vulnerability.is_kev == True)  # noqa: E712
    return w


async def _owners(db, device_ids: list[str]) -> dict[str, dict]:
    """Per asset: its application and technical owner, read through the tag mapping."""
    from api.core import tag_roles
    from api.models.tag import Tag
    roles = await tag_roles.ensure(db)
    names: dict[str, list[str]] = {}
    for dev, name in (await db.execute(select(DeviceTag.device_id, Tag.name).join(Tag, Tag.id == DeviceTag.tag_id)
                                       .where(DeviceTag.device_id.in_(device_ids or ["__none__"])))).all():
        names.setdefault(str(dev), []).append(name)
    return {d: {"app": ", ".join(tag_roles.values(t, "application", roles)[:2]),
                "tech": ", ".join(tag_roles.values(t, "technical_owner", roles)[:2])} for d, t in names.items()}


async def _queue(ctx, p):
    from api.core import sla
    from api.routes import device_query as dq
    await sla.load(ctx.db)
    spread = p.get("rows") == "vulnerability"   # one row per vulnerability (its oldest finding), not per asset
    found = (await ctx.db.execute(
        select(Finding, Vulnerability, Device.hostname).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .join(Device, Device.id == Finding.device_id).where(*_w(ctx, p))
        .order_by(Vulnerability.is_kev.desc(), Vulnerability.cvss_base.desc().nulls_last(), Finding.first_detected.asc())
        .limit(p["limit"] * (40 if spread else 1)))).all()
    rows, seen = [], set()
    for r in found:
        if spread and r[1].id in seen:
            continue
        seen.add(r[1].id)
        rows.append(r)
        if len(rows) >= p["limit"]:
            break
    others = {}
    if spread and rows:
        others = dict((await ctx.db.execute(select(Finding.vuln_id, func.count(func.distinct(Finding.device_id)))
                                            .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                                            .where(*_w(ctx, p), Finding.vuln_id.in_([v.id for _, v, _ in rows]))
                                            .group_by(Finding.vuln_id))).all())
    who = await _owners(ctx.db, list({str(f.device_id) for f, _, _ in rows}))
    out, hrefs = [], []
    for f, v, host in rows:
        a = finding_age.view(f.first_detected, f.last_seen, f.status.value, v.cvss_base)
        sev = finding_age.severity(v.cvss_base)
        due = (f.first_detected + timedelta(days=a["sla_days"])) if f.first_detected and a["sla_days"] else None
        o = who.get(str(f.device_id), {})
        name = host if f.domain in ("code", "web") else dq.short_name(host)
        more = (others.get(v.id) or 1) - 1
        name = f"{name} (+{more:,} more)" if more > 0 else name
        out.append([{"v": sev.title(), "tone": SEV_TONE[sev]}, (f"{v.cve_id} " if v.cve_id else "") + (v.title or "")[:90]
                    + (" (KEV)" if v.is_kev else ""), name, o.get("app") or "", o.get("tech") or "",
                    {"v": f"{a['age_days']}d" if a["age_days"] is not None else "", "tone": "critical" if a["past_sla"] else ""},
                    {"v": "Overdue", "tone": "critical"} if a["past_sla"] else (due.date().isoformat() if due else ""),
                    f.source.replace("_", " ")])
        hrefs.append(f"/vulns/{v.id}")
    return {"columns": ["Severity", "Issue", "Asset", "Application", "Technical owner", "Age", "Due", "Source"],
            "rows": out, "hrefs": hrefs}


async def _age_kpi(ctx, p):
    age = days_since(ctx.db, Finding.first_detected)
    n, avg, top = (await ctx.db.execute(select(func.count(), func.avg(age), func.max(age)).select_from(Finding)
                                        .join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(*_w(ctx, p)))).one()
    avg_d, top_d = (None if avg is None else int(round(float(avg)))), (None if top is None else int(round(float(top))))
    what = {"any": "open findings", "infra": "open infrastructure findings", "code": "open code findings", "web": "open web app findings"}[p["type"]]
    sev = "" if p["severity"] == "any" else SEVERITY.labels.get(p["severity"], p["severity"]).lower() + " "
    note = f"{n:,} {sev}{what}" + (f" · average age {avg_d} days · oldest {top_d} days" if n else "")
    value = {"count": n, "avg_age": avg_d, "max_age": top_d}[p["measure"]]
    return {"value": value, "unit": "" if p["measure"] == "count" else " days", "href": "/vulns?sort=age", "note": note}


C = "Vulnerabilities"
ROWS = Param("rows", "One row per", ("vulnerability", "finding"),
             labels={"vulnerability": "Vulnerability (its oldest asset, with how many more)", "finding": "Finding (each asset)"})
metric(Metric("vuln.action_queue", "Priority action queue", C, "table", (LIMIT, ROWS, TYPE, SEVERITY, SOURCE, KEV), _queue,
              "The highest-risk open findings to work first (known exploited, then severity, then oldest), with "
              "severity, issue, asset, application, technical owner, age, due date (from the SLA) and source."))
metric(Metric("vuln.age", "Vulnerability age", C, "value",
              (Param("measure", "Number", MEASURES, labels=MEASURE_LABEL), TYPE, SEVERITY, KEV, SOURCE), _age_kpi,
              "How many open findings, with their average and oldest age in days (for example critical and high "
              "issues: 23, average 31 days, oldest 184)."))
