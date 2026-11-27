"""Vulnerability dashboard numbers: today's posture, trends rebuilt from finding dates, aging, MTTR, top lists.

Trends need no snapshot table. A finding counts as open on day D if it was first detected on or before D and
is still open, or was remediated after D. So open(D) = sum(new up to D) - sum(fixed up to D), where "new" is
every open or remediated finding by first-detected day and "fixed" is every remediated finding by its last-seen
day. That is exact for everything CTEM has tracked; findings fixed before CTEM started aren't in the data, so
points before `tracking_since` read low (the page says so). Remediated findings removed after the retention window
are counted back in from their daily rollup (api/core/finding_history.py) when the view's filters are ones the
rollup records (source, kind of work); a view narrowed to a device type, scope or repository covers the window only.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import Date, and_, case, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.device import Device, DeviceType
from api.models.vuln import ExceptionStatus, Finding, FindingStatus, Vulnerability, VulnException

log = logging.getLogger("open-ctem.vuln_dashboard")

SEVERITIES = ("critical", "high", "medium", "low")
RANGES = {"30d": 30, "90d": 90, "180d": 180, "365d": 365, "all": None}
SOURCES = ("rapid7_insightvm", "rapid7_appsec", "rapid7_cloudsec", "qualys", "tenable", "msdefender", "snyk",
           "github_advanced", "forgerepo", "crowdstrike", "crowdstrike_spotlight", "github_code_review", "horizon3")
# The type of work (api.core.finding_domain): infra, code or web. "all" applies no type filter (dashboard widgets).
KINDS = ("infra", "code", "web", "cloud", "all")
# Days to fix by severity; updated in place from the install's setting (api/core/sla.py, Change SLAs)
SLA_DAYS = {"critical": 15, "high": 30, "medium": 90, "low": 180}
AGE_BUCKETS = ((0, 30, "0-30 days"), (31, 60, "31-60"), (61, 90, "61-90"), (91, 180, "91-180"), (181, None, "180+"))
OPEN = (FindingStatus.open, FindingStatus.in_progress)
DIRTY_KEY = "vulndash:dirty_at"   # when the data last changed; a view built before it is out of date
VIEWERS_KEY = "vulndash:scoped_viewers"   # people who see only some devices and opened the dashboard lately
VIEWER_DAYS, MAX_WARM_VIEWERS = 7, 25


def _sev():
    c = Vulnerability.cvss_base
    return case((c >= 9.0, "critical"), (c >= 7.0, "high"), (c >= 4.0, "medium"), else_="low")


async def configured_sources(db) -> list[str]:
    """The finding sources this install actually has an integration for (enabled or not), in SOURCES order."""
    from api.models.integration import IntegrationConfig
    have = {v.value if hasattr(v, "value") else str(v) for (v,) in (await db.execute(select(IntegrationConfig.vendor).distinct())).all()}
    return [s for s in SOURCES if s in have]


def _where(source: str | list | None, device_type: str | None, kind: str = "all", code: dict | None = None) -> list:
    """Allow-listed filters only, so nothing a client sends reaches SQL as text.
    Contained and Not In Scope devices never count (their findings can't be reached right now).
    kind: infra, code or web findings only, or "all" for every one. code: Code tab picks, pre-checked."""
    from api.core.device_scope_exempt import in_scope_findings
    out = [in_scope_findings()]
    if kind in ("infra", "code", "web", "cloud"):
        out.append(Finding.domain == kind)
    srcs = [x for x in ([source] if isinstance(source, str) else list(source or [])) if x in SOURCES]
    if len(srcs) == 1:
        out.append(Finding.source == srcs[0])
    elif srcs:   # several sources picked (a dashboard widget)
        out.append(Finding.source.in_(srcs))
    if device_type in DeviceType.__members__:
        out.append(Finding.device_id.in_(select(Device.id).where(Device.device_type == DeviceType[device_type])))
    if code and kind == "code":
        repos = select(Device.id).where(Device.device_type == DeviceType.code_repository)
        if code.get("repo"):
            out.append(Finding.device_id.in_(repos.where(Device.hostname == code["repo"])))
        if code.get("org"):   # a repository is named "org/name"; the org's own _ and % are not wildcards
            esc = code["org"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            out.append(Finding.device_id.in_(repos.where(Device.hostname.like(f"{esc}/%", escape="\\"))))
        if code.get("app_tags"):
            from api.models.device import DeviceTag
            from api.models.tag import Tag
            out.append(Finding.device_id.in_(select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id)
                                             .where(Tag.name.in_(list(code["app_tags"])[:50]))))
    return out


async def code_filters(db, scope=None) -> dict:
    """Repos this viewer may see, with org and apps; client picks are checked against this list."""
    from api.core import tag_roles
    from api.models.device import DeviceTag
    from api.models.tag import Tag
    cond = [Device.device_type == DeviceType.code_repository] + ([scope] if scope is not None else [])
    rows = (await db.execute(select(Device.id, Device.hostname).where(*cond).order_by(Device.hostname))).all()
    roles = await tag_roles.ensure(db)
    tags = (await db.execute(select(DeviceTag.device_id, Tag.name).join(Tag, Tag.id == DeviceTag.tag_id)
                             .where(DeviceTag.device_id.in_(select(Device.id).where(*cond))))).all()
    apps_of: dict = {}
    app_tags: dict[str, set] = {}
    for did, name in tags:
        m = tag_roles.match(name, roles)
        if m and m[0] == "application":
            apps_of.setdefault(did, set()).add(m[1])
            app_tags.setdefault(m[1], set()).add(name)
    repos = [{"name": h, "org": h.split("/", 1)[0] if "/" in h else "", "apps": sorted(apps_of.get(i, ()), key=str.lower)}
             for i, h in rows if h]
    return {"orgs": sorted({r["org"] for r in repos if r["org"]}, key=str.lower), "repos": repos,
            "apps": [{"value": v, "tags": sorted(t)} for v, t in sorted(app_tags.items(), key=lambda x: x[0].lower())]}


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _kpis(db, w) -> dict:
    """Every headline number in one pass over the findings."""
    sev, age = _sev(), func.extract("epoch", _now() - Finding.first_detected) / 86400
    is_open = Finding.status.in_(OPEN)
    week = _now() - timedelta(days=7)
    past = or_(*[and_(sev == s, age > d) for s, d in SLA_DAYS.items() if s in ("critical", "high")])
    fixed = Finding.status == FindingStatus.remediated
    q = (select(func.count().filter(is_open), *[func.count().filter(is_open, sev == s) for s in SEVERITIES],
                func.count().filter(is_open, Vulnerability.is_kev == True),  # noqa: E712
                func.count().filter(is_open, Vulnerability.exploit_available == True),  # noqa: E712
                func.count().filter(is_open, past),
                func.count().filter(Finding.first_detected >= week, Finding.status.not_in((FindingStatus.false_positive, FindingStatus.merged))),
                func.count().filter(fixed, Finding.last_seen >= week),
                func.count().filter(Finding.exception_id.is_not(None)),
                func.min(Finding.last_seen).filter(fixed))
         .select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(*w))
    r = (await db.execute(q)).one()

    async def distinct_open(col) -> int:   # GROUP BY runs in parallel; COUNT(DISTINCT) doesn't
        sub = select(col).where(Finding.status.in_(OPEN), *w).group_by(col).subquery()
        return (await db.execute(select(func.count()).select_from(sub))).scalar_one()
    return {"open": r[0], **{s: r[i + 1] for i, s in enumerate(SEVERITIES)}, "kev": r[5], "exploitable": r[6],
            "past_sla": r[7], "devices": await distinct_open(Finding.device_id), "vulns": await distinct_open(Finding.vuln_id),
            "new_7d": r[8], "fixed_7d": r[9], "excepted": r[10], "_fixes_since": r[11].date().isoformat() if r[11] else None}


async def _units(db, w) -> dict:
    """The headline counts as unique vulnerabilities and as fixes, for the dashboard's Count switch. A fix counts
    under Critical when any finding it resolves is critical, under KEV when any is known exploited, and so on."""
    from api.models.vuln import Fix
    rank = case((Vulnerability.cvss_base >= 9.0, 4), (Vulnerability.cvss_base >= 7.0, 3),
                (Vulnerability.cvss_base >= 4.0, 2), else_=1)
    kev = func.max(case((Vulnerability.is_kev == True, 1), else_=0))  # noqa: E712
    exp = func.max(case((Vulnerability.exploit_available == True, 1), else_=0))  # noqa: E712
    out = {}
    for unit, col in (("vulns", Finding.vuln_id), ("fixes", Finding.fix_key)):
        sub = (select(col.label("k"), func.max(rank).label("r"), kev.label("kev"), exp.label("exp"))
               .select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
               .where(Finding.status.in_(OPEN), col.is_not(None), *w).group_by(col).subquery())
        r = (await db.execute(select(func.count(), *[func.count().filter(sub.c.r == n) for n in (4, 3, 2, 1)],
                                     func.count().filter(sub.c.kev == 1), func.count().filter(sub.c.exp == 1))
                              .select_from(sub))).one()
        out[unit] = {"open": r[0], **{s: r[i + 1] for i, s in enumerate(SEVERITIES)}, "kev": r[5], "exploitable": r[6]}
    # Open findings by their risk grade (F worst), for the Count switch's Risk grade view
    g = (await db.execute(select(Finding.risk_grade, func.count()).select_from(Finding)
                          .where(Finding.status.in_(OPEN), *w).group_by(Finding.risk_grade))).all()
    out["grades"] = {k: 0 for k in "FDCBA"} | {k: n for k, n in g if k and k in "FDCBA"}
    # Findings no source has named a fix for yet: shown so the Fixes count is never mistaken for everything
    out["fixes"]["unassigned_findings"] = (await db.execute(
        select(func.count()).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(Finding.status.in_(OPEN), Finding.fix_key.is_(None), *w))).scalar_one()
    # The fixes that remove the most risk: critical findings first, then how many findings, then known exploited
    crit = func.count().filter(Vulnerability.cvss_base >= 9.0)
    top = (await db.execute(
        select(Finding.fix_key, func.count(), crit, func.count().filter(Vulnerability.is_kev == True),  # noqa: E712
               func.count(func.distinct(Finding.vuln_id)), func.count(func.distinct(Finding.device_id)))
        .select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(Finding.status.in_(OPEN), Finding.fix_key.is_not(None), *w)
        .group_by(Finding.fix_key).order_by(crit.desc(), func.count().desc()).limit(25))).all()
    names = {f.key: f for f in (await db.execute(select(Fix).where(Fix.key.in_([t[0] for t in top])))).scalars()}
    out["top_fixes"] = [{"key": k, "title": (names[k].title if k in names else k.split(":", 1)[-1])[:200],
                         "kind": names[k].kind if k in names else None, "findings": n, "critical": c, "kev": kv,
                         "vulns": nv, "devices": nd} for k, n, c, kv, nv, nd in top]
    return out


async def _trend(db, w, days: int | None, roll=None) -> dict:
    """Daily open count by severity (and KEV), plus new and fixed per day, over the range. roll: the rolled-up
    removed findings this view covers (finding_history.roll_for), or None."""
    sev = _sev()
    d_new = cast(func.date_trunc("day", Finding.first_detected), Date)
    d_fix = cast(func.date_trunc("day", Finding.last_seen), Date)
    new_rows = (await db.execute(
        select(d_new, sev, Vulnerability.is_kev, func.count()).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(Finding.status.in_([*OPEN, FindingStatus.remediated]), Finding.first_detected.is_not(None), *w)
        .group_by(d_new, sev, Vulnerability.is_kev))).all()
    fix_rows = (await db.execute(
        select(d_fix, sev, Vulnerability.is_kev, func.count()).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(Finding.status == FindingStatus.remediated, Finding.last_seen.is_not(None), *w)
        .group_by(d_fix, sev, Vulnerability.is_kev))).all()
    if roll is not None:
        from api.core import finding_history as fh
        new_rows, fix_rows = [*new_rows, *await fh.by_day(db, roll, "new")], [*fix_rows, *await fh.by_day(db, roll, "fixed")]
    return series(new_rows, fix_rows, _now().date(), days)


def series(new_rows, fix_rows, today, days: int | None) -> dict:
    """Rows are (day, severity, is_kev, count). Open on day D = new up to D minus fixed up to D."""
    first = min([r[0] for r in new_rows if r[0]] or [today])
    start = max(first, today - timedelta(days=days - 1)) if days else first
    keys = [*SEVERITIES, "kev"]
    delta: dict = {}
    new_day: dict = {}
    fix_day: dict = {}
    for rows, sign, per in ((new_rows, 1, new_day), (fix_rows, -1, fix_day)):
        for d, s, kev, n in rows:
            if d is None:
                continue
            d = min(d, today)
            bucket = delta.setdefault(d, dict.fromkeys(keys, 0))
            bucket[s] += sign * n
            if kev:
                bucket["kev"] += sign * n
            per[d] = per.get(d, 0) + n
    running = dict.fromkeys(keys, 0)
    for d in sorted(x for x in delta if x < start):
        for k in keys:
            running[k] += delta[d][k]
    out: dict = {"days": [], **{k: [] for k in keys}, "new": [], "fixed": []}
    d = start
    while d <= today:
        for k in keys:
            running[k] += delta.get(d, {}).get(k, 0)
            out[k].append(max(running[k], 0))
        out["days"].append(d.isoformat())
        out["new"].append(new_day.get(d, 0))
        out["fixed"].append(fix_day.get(d, 0))
        d += timedelta(days=1)
    return out


async def _aging(db, w) -> dict:
    sev, age = _sev(), func.extract("epoch", _now() - Finding.first_detected) / 86400
    bucket = case(*[((age <= hi) if hi else (age >= lo), label) for lo, hi, label in AGE_BUCKETS[:-1]],
                  else_=AGE_BUCKETS[-1][2])
    rows = (await db.execute(select(bucket, sev, func.count()).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                             .where(Finding.status.in_(OPEN), *w).group_by(bucket, sev))).all()
    labels = [b[2] for b in AGE_BUCKETS]
    out = {"buckets": labels, **{s: [0] * len(labels) for s in SEVERITIES}}
    for b, s, n in rows:
        out[s][labels.index(b)] += n
    return out


async def _mttr(db, w, roll=None) -> dict:
    """Mean days to remediate, by month the fix was seen, for critical and high (rolled-up fixes counted in)."""
    sev, month = _sev(), cast(func.date_trunc("month", Finding.last_seen), Date)
    days = func.avg(func.extract("epoch", Finding.last_seen - Finding.first_detected) / 86400)
    rows = (await db.execute(select(month, sev, days, func.count()).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                             .where(Finding.status == FindingStatus.remediated, Finding.first_detected.is_not(None),
                                    Finding.last_seen >= _now() - timedelta(days=365), *w)
                             .group_by(month, sev))).all()
    if roll is not None:
        from api.core import finding_history as fh
        live = {(m, s): (float(a or 0) * n, n) for m, s, a, n in rows}
        for k, (n, took) in (await fh.fix_time_by_month(db, roll, (_now() - timedelta(days=365)).date())).items():
            t, c = live.get(k, (0.0, 0))
            live[k] = (t + took, c + n)
        rows = [(m, s, (t / c) if c else None, c) for (m, s), (t, c) in live.items()]
    months = sorted({r[0] for r in rows})
    out = {"months": [m.isoformat()[:7] for m in months], **{s: [None] * len(months) for s in SEVERITIES}}
    for m, s, avg, _n in rows:
        out[s][months.index(m)] = round(float(avg or 0), 1)
    return out


async def _breakdowns(db, w, kind: str = "all") -> dict:
    by_source = (await db.execute(select(Finding.source, func.count()).where(Finding.status.in_(OPEN), *w)
                                  .group_by(Finding.source).order_by(func.count().desc()).limit(10))).all()
    by_type = (await db.execute(select(Device.device_type, func.count()).select_from(Finding).join(Device, Device.id == Finding.device_id)
                                .where(Finding.status.in_(OPEN), *w).group_by(Device.device_type)
                                .order_by(func.count().desc()))).all()
    cols = (Vulnerability.id, Vulnerability.cve_id, Vulnerability.title, Vulnerability.cvss_base, Vulnerability.is_kev)
    # w[0] is always the "counts" condition from _where, and a kind adds one more; the rest are real filters
    filtered = len(w) > (1 if kind == "all" else 2)
    other = select(Finding.device_id).where(Finding.domain.in_(("code", "web")))   # few rows, through the index
    if filtered:   # one finding per device and vulnerability, so counting findings counts devices
        n = func.count()
        top_v = (await db.execute(select(*cols, n).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                                  .where(Finding.status.in_(OPEN), *w).group_by(*cols).order_by(n.desc()).limit(10))).all()
    else:   # the scoring engine keeps this count up to date already (it skips contained devices too)
        vk = [Vulnerability.domain == kind] if kind != "all" else []
        top_v = (await db.execute(select(*cols, Vulnerability.affected_devices).where(Vulnerability.affected_devices > 0, *vk)
                                  .order_by(Vulnerability.affected_devices.desc()).limit(10))).all()
    dev_w = [Device.open_findings > 0]
    if not filtered and kind in ("code", "web"):
        dev_w.append(Device.id.in_(select(Finding.device_id).where(Finding.domain == kind)))
    elif not filtered and kind == "infra":   # repositories and web apps have their own tabs
        dev_w.append(Device.id.not_in(other))
    top_d = (await db.execute(select(Device.id, Device.hostname, Device.risk_score, Device.risk_grade, Device.open_findings,
                                     Device.kev_findings).where(*dev_w, *([Device.id.in_(select(Finding.device_id).where(*w))] if filtered else []))
                              .order_by(Device.risk_score.desc().nulls_last()).limit(10))).all()
    from api.routes import device_query as dq
    return {"by_source": [{"source": s, "open": n} for s, n in by_source],
            "by_type": [{"type": t.value if t else "unknown", "open": n} for t, n in by_type],
            "top_vulns": [{"id": str(i), "cve_id": c, "title": (t or "")[:200], "cvss": cv, "kev": bool(k), "devices": n}
                          for i, c, t, cv, k, n in top_v],
            "top_devices": [{"id": str(i), "hostname": dq.short_name(h), "score": s, "grade": g.value if g else None,
                             "open": o, "kev": kv} for i, h, s, g, o, kv in top_d]}


async def _exceptions(db) -> dict:
    now = _now()
    active = (await db.execute(select(func.count()).select_from(VulnException).where(
        VulnException.status == ExceptionStatus.approved, VulnException.expires_at > now))).scalar_one()
    pending = (await db.execute(select(func.count()).select_from(VulnException).where(
        VulnException.status == ExceptionStatus.pending))).scalar_one()
    soon = (await db.execute(select(func.count()).select_from(VulnException).where(
        VulnException.status == ExceptionStatus.approved, VulnException.expires_at > now,
        VulnException.expires_at <= now + timedelta(days=14)))).scalar_one()
    return {"active": active, "pending": pending, "ending_14d": soon}


def scoped(scope) -> list:
    """Limit findings to the devices a scoped viewer may see (scope: a Device WHERE clause, or None for all)."""
    return [] if scope is None else [Finding.device_id.in_(select(Device.id).where(scope))]


async def build(db: AsyncSession, source: str | None, device_type: str | None, scope=None, kind: str = "all",
                code: dict | None = None) -> dict:
    """Everything for one filter combination, with the trend over the whole history (ranges are sliced later)."""
    from api.core import sla
    await sla.load(db)
    from api.core import finding_history as fh
    w = _where(source, device_type, kind, code) + scoped(scope)
    roll = fh.roll_for(source, device_type, scope, kind, code)
    k = await _kpis(db, w)
    since = k.pop("_fixes_since")
    rolled = await fh.first_fix(db, roll) if roll is not None else None
    if rolled is not None and (since is None or rolled.isoformat() < since):
        since = rolled.isoformat()
    return {"generated_at": _now().isoformat(), "tracking_since": since, "sla_days": SLA_DAYS,
            "kpis": k, "trend": await _trend(db, w, None, roll), "aging": await _aging(db, w), "mttr": await _mttr(db, w, roll),
            **await _breakdowns(db, w, kind), "units": await _units(db, w),
            # exception counts are fleet-wide, so scoped viewers don't get them
            "exceptions": await _exceptions(db) if scope is None else {"active": None, "pending": 0, "ending_14d": 0}}


# The cache of built views (one build per view, kept and refreshed in the background): api/core/vuln_dashboard_cache.py
from api.core.vuln_dashboard_cache import (CACHE_SECONDS, WAIT_SECONDS, _rebuild_later, cached, forget_cached,  # noqa: E402,F401
                                           sliced, warm)
