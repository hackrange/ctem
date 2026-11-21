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


def _now():
    return datetime.now(timezone.utc)


def stale_computers(days: int, scope=None):
    """Conditions for AD computer objects with no logon for `days` (never logged on counts as stale)."""
    cut = _now() - timedelta(days=days)
    w = [Device.ad_joined.is_(True), or_(Device.ad_last_logon.is_(None), Device.ad_last_logon < cut)]
    return w + ([scope] if scope is not None else [])


def stale_users(days: int):
    """Enabled directory user accounts with no logon for `days`."""
    from api.models.user import User
    cut = _now() - timedelta(days=days)
    return [User.ad_last_logon.is_not(None) | User.ad_disabled.is_not(None), User.ad_disabled.is_not(True),
            or_(User.ad_last_logon.is_(None), User.ad_last_logon < cut)]


async def _computers(ctx, p):
    n = (await ctx.db.execute(select(func.count()).select_from(Device).where(*stale_computers(p["days"], ctx.scope)))).scalar_one()
    total = (await ctx.db.execute(select(func.count()).select_from(Device).where(
        Device.ad_joined.is_(True), *([ctx.scope] if ctx.scope is not None else [])))).scalar_one()
    return {"value": n, "note": f"of {total:,} AD computers with no logon in {p['days']} days",
            "href": f"/devices?ad_stale_days={p['days']}"}


async def _users(ctx, p):
    from api.models.user import User
    n = (await ctx.db.execute(select(func.count()).select_from(User).where(*stale_users(p["days"])))).scalar_one()
    return {"value": n, "note": f"enabled AD users with no logon in {p['days']} days", "href": "/users"}


async def _list(ctx, p):
    from api.routes import device_query as dq
    rows = (await ctx.db.execute(select(Device).where(*stale_computers(p["days"], ctx.scope))
                                 .order_by(Device.ad_last_logon.asc().nulls_first()).limit(p["limit"]))).scalars().all()
    now = _now()

    def ago(d):
        if not d:
            return "never"
        d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        return f"{(now - d).days:,} days"
    ou = lambda dn: ",".join(x for x in (dn or "").split(",") if x.strip().upper().startswith("OU="))[:80]  # noqa: E731
    return {"columns": ["Computer", "Last AD logon", "OU"],
            "rows": [[dq.short_name(d.hostname), ago(d.ad_last_logon), ou(d.ad_dn)] for d in rows],
            "hrefs": [f"/devices/{d.id}" for d in rows]}


async def _trend(ctx, p):
    from api.models.snapshot import MetricSnapshot
    if p["kind"] == "computers" and ctx.scope is not None:
        return {"error": "The stale trend covers every device, so it's for fleet-wide viewers."}
    days = {"30d": 30, "90d": 90, "180d": 180, "365d": 365}[p["range"]]
    start = date.today() - timedelta(days=days - 1)
    keys = [f"stale_{p['kind']}_{t}" for t in THRESHOLDS]
    rows = (await ctx.db.execute(select(MetricSnapshot.key, MetricSnapshot.day, MetricSnapshot.value)
                                 .where(MetricSnapshot.key.in_(keys), MetricSnapshot.day >= start))).all()
    x = [(start + timedelta(days=i)).isoformat() for i in range(days)]
    grid = {k: dict.fromkeys(x) for k in keys}
    for k, d, v in rows:
        if d.isoformat() in grid[k]:
            grid[k][d.isoformat()] = v
    colors = {21: "--severity-medium", 30: "--severity-high", 90: "--severity-critical"}
    have = sum(1 for k, d, v in rows)
    return {"x": x, "series": [{"name": f"{t}+ days", "data": list(grid[f"stale_{p['kind']}_{t}"].values()), "color": colors[t]}
                               for t in THRESHOLDS],
            "note": None if have > 3 else "The trend builds from a daily snapshot that started recently."}


D = "Directory"
metric(Metric("directory.stale_computers", "Stale AD computer objects", D, "value", (DAYS,), _computers,
              "AD computer objects with no logon for the chosen number of days. Click through to the list."))
metric(Metric("directory.stale_users", "Stale AD user accounts", D, "value", (DAYS,), _users,
              "Enabled AD user accounts with no logon for the chosen number of days.", needs="threats"))
metric(Metric("directory.stale_computers_list", "Stale AD computers (list)", D, "table", (DAYS, LIMIT), _list,
              "The stalest AD computer objects first, with their last logon and OU."))
metric(Metric("directory.stale_trend", "Stale AD objects over time", D, "series", (KIND, RANGE), _trend,
              "Daily count of stale objects at 21, 30 and 90 days.", needs="threats"))


async def record_snapshots(db) -> int:
    """Today's stale counts at every snapshot threshold, fleet-wide (overwrites today's earlier values)."""
    from api.models.snapshot import MetricSnapshot
    from api.models.user import User
    today, n = date.today(), 0
    for t in SNAPSHOT_DAYS:
        for kind, q in (("computers", select(func.count()).select_from(Device).where(*stale_computers(t))),
                        ("users", select(func.count()).select_from(User).where(*stale_users(t)))):
            await db.merge(MetricSnapshot(key=f"stale_{kind}_{t}", day=today, value=(await db.execute(q)).scalar_one()))
            n += 1
    await db.commit()
    return n
