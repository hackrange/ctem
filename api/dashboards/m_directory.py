"""Directory (AD) hygiene widgets: stale computer and user objects at any threshold, a list of them, and a trend
from the daily snapshots. Computers follow the viewer's device scope; user counts and trends are fleet-wide, so
only admin and cyber see them."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, or_, select

from api.dashboards.catalog import Metric, Param, metric
from api.models.device import Device

DAYS = Param("days", "Stale after (days without a logon)", low=1, high=3650, default=90)
THRESHOLDS = (21, 30, 90)                 # the lines on the trend chart
SNAPSHOT_DAYS = (7, 14, 21, 30, 45, 60, 90, 180, 365)   # what the daily job records
RANGE = Param("range", "Range", ("90d", "30d", "180d", "365d"),
              labels={"30d": "30 days", "90d": "90 days", "180d": "180 days", "365d": "1 year"})
KIND = Param("kind", "Objects", ("computers", "users"), labels={"computers": "Computer objects", "users": "User accounts"})
LIMIT = Param("limit", "Rows", low=3, high=50, default=15)
# A computer a scanner or EDR has heard from recently is alive, whatever AD says, so it isn't a stale object.
QUIET = Param("tools_quiet", "Leave out computers a scanner or EDR saw in the last",
              ("21", "off", "7", "14", "30", "45", "60", "90"),
              labels={"off": "Don't check other tools", **{d: f"{d} days" for d in ("7", "14", "21", "30", "45", "60", "90")}})
QUIET_DAYS = 21   # the default above, and what the "no tool contact" trend snapshots use


def _now():
    return datetime.now(timezone.utc)


def stale_computers(days: int, scope=None, quiet_days: int | None = None):
    """Conditions for AD computer objects with no logon for `days` (never logged on counts as stale).
    quiet_days: also require that no vulnerability scanner and no EDR has reported the computer in that many
    days (never counts as quiet), so live machines with an old AD logon stay off the list."""
    cut = _now() - timedelta(days=days)
    w = [Device.ad_joined.is_(True), or_(Device.ad_last_logon.is_(None), Device.ad_last_logon < cut)]
    if quiet_days:
        q = _now() - timedelta(days=quiet_days)
        w += [or_(Device.last_seen.is_(None), Device.last_seen < q), or_(Device.edr_last_seen.is_(None), Device.edr_last_seen < q)]
    return w + ([scope] if scope is not None else [])


def _quiet(p) -> int | None:
    v = p.get("tools_quiet", str(QUIET_DAYS))
    return None if v == "off" else int(v)


def stale_users(days: int):
    """Enabled directory user accounts with no logon for `days`."""
    from api.models.user import User
    cut = _now() - timedelta(days=days)
    return [User.ad_last_logon.is_not(None) | User.ad_disabled.is_not(None), User.ad_disabled.is_not(True),
            or_(User.ad_last_logon.is_(None), User.ad_last_logon < cut)]


async def _computers(ctx, p):
    q = _quiet(p)
    n = (await ctx.db.execute(select(func.count()).select_from(Device).where(*stale_computers(p["days"], ctx.scope, q)))).scalar_one()
    total = (await ctx.db.execute(select(func.count()).select_from(Device).where(
        Device.ad_joined.is_(True), *([ctx.scope] if ctx.scope is not None else [])))).scalar_one()
    return {"value": n, "note": f"of {total:,} AD computers with no logon in {p['days']} days"
                              + (f" and no scanner or EDR contact in {q} days" if q else ""),
            "href": f"/devices?ad_stale_days={p['days']}" + (f"&ad_tools_quiet_days={q}" if q else "")}


async def _users(ctx, p):
    from api.models.user import User
    n = (await ctx.db.execute(select(func.count()).select_from(User).where(*stale_users(p["days"])))).scalar_one()
    return {"value": n, "note": f"enabled AD users with no logon in {p['days']} days", "href": "/users"}


async def _list(ctx, p):
    from api.routes import device_query as dq
    rows = (await ctx.db.execute(select(Device).where(*stale_computers(p["days"], ctx.scope, _quiet(p)))
                                 .order_by(Device.ad_last_logon.asc().nulls_first()).limit(p["limit"]))).scalars().all()
    now = _now()

    def ago(d):
        if not d:
            return "never"
        d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        return f"{(now - d).days:,} days"
    ou = lambda dn: ",".join(x for x in (dn or "").split(",") if x.strip().upper().startswith("OU="))[:80]  # noqa: E731
    tool = lambda d: ago(max([x for x in (d.last_seen, d.edr_last_seen) if x], default=None, key=lambda x: x if x.tzinfo else x.replace(tzinfo=timezone.utc)))  # noqa: E731
    return {"columns": ["Computer", "Last AD logon", "Last scanner or EDR contact", "OU"],
            "rows": [[dq.short_name(d.hostname), ago(d.ad_last_logon), tool(d), ou(d.ad_dn)] for d in rows],
            "hrefs": [f"/devices/{d.id}" for d in rows]}


async def _trend(ctx, p):
    from api.models.snapshot import MetricSnapshot
    if p["kind"] == "computers" and ctx.scope is not None:
        return {"error": "The stale trend covers every device, so it's for fleet-wide viewers."}
    days = {"30d": 30, "90d": 90, "180d": 180, "365d": 365}[p["range"]]
    start = date.today() - timedelta(days=days - 1)
    quiet = p["kind"] == "computers" and p.get("tools_quiet", "on") == "on"
    pre = "stale_computers_quiet" if quiet else f"stale_{p['kind']}"
    keys = [f"{pre}_{t}" for t in THRESHOLDS]
    rows = (await ctx.db.execute(select(MetricSnapshot.key, MetricSnapshot.day, MetricSnapshot.value)
                                 .where(MetricSnapshot.key.in_(keys), MetricSnapshot.day >= start))).all()
    x = [(start + timedelta(days=i)).isoformat() for i in range(days)]
    grid = {k: dict.fromkeys(x) for k in keys}
    for k, d, v in rows:
        if d.isoformat() in grid[k]:
            grid[k][d.isoformat()] = v
    colors = {21: "--severity-medium", 30: "--severity-high", 90: "--severity-critical"}
    have = sum(1 for k, d, v in rows)
    return {"x": x, "series": [{"name": f"{t}+ days", "data": list(grid[f"{pre}_{t}"].values()), "color": colors[t]}
                               for t in THRESHOLDS],
            "note": None if have > 3 else "The trend builds from a daily snapshot that started recently."}


D = "Directory"
metric(Metric("directory.stale_computers", "Stale AD computer objects", D, "value", (DAYS, QUIET), _computers,
              "AD computer objects with no logon for the chosen number of days that no scanner or EDR has seen recently "
              "(21 days unless changed). Click through to the list."))
metric(Metric("directory.stale_users", "Stale AD user accounts", D, "value", (DAYS,), _users,
              "Enabled AD user accounts with no logon for the chosen number of days.", needs="threats", filterable=False))
metric(Metric("directory.stale_computers_list", "Stale AD computers (list)", D, "table", (DAYS, QUIET, LIMIT), _list,
              "The stalest AD computer objects first, with their last logon, last scanner or EDR contact, and OU."))
metric(Metric("directory.stale_trend", "Stale AD objects over time", D, "series",
              (KIND, RANGE, Param("tools_quiet", "Computers", ("on", "off"),
                                  labels={"on": "Only those no scanner or EDR saw in 21 days", "off": "Every stale AD object"})),
              _trend, "Daily count of stale objects at 21, 30 and 90 days.", needs="threats", filterable=False))


async def record_snapshots(db) -> int:
    """Today's stale counts at every snapshot threshold, fleet-wide (overwrites today's earlier values)."""
    from api.models.snapshot import MetricSnapshot
    from api.models.user import User
    today, n = date.today(), 0
    for t in SNAPSHOT_DAYS:
        for kind, q in (("computers", select(func.count()).select_from(Device).where(*stale_computers(t))),
                        ("computers_quiet", select(func.count()).select_from(Device).where(*stale_computers(t, None, QUIET_DAYS))),
                        ("users", select(func.count()).select_from(User).where(*stale_users(t)))):
            await db.merge(MetricSnapshot(key=f"stale_{kind}_{t}", day=today, value=(await db.execute(q)).scalar_one()))
            n += 1
    await db.commit()
    return n
