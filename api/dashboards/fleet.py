"""Shared pieces for the risk and asset widgets: OS families, coverage conditions, cloud devices, daily snapshots,
resampling a daily series into weeks or months, and the "12.4% decrease over the last month" headline.

Everything here is vendor generic: a scanner is any vulnerability scanner feed, an EDR is whichever EDR reported."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import case, func, or_, select

from api.models.device import Device, DeviceType

OS_FAMILIES = ("windows", "linux", "macos", "network", "mobile", "hypervisor", "unix", "other", "unknown")
OS_LABEL = {"windows": "Windows", "linux": "Linux", "macos": "macOS", "network": "Network OS", "mobile": "Mobile",
            "hypervisor": "Hypervisor", "unix": "Unix", "other": "Other", "unknown": "Unknown"}
BUCKETS = ("week", "day", "month")
BUCKET_LABEL = {"day": "Daily", "week": "Weekly", "month": "Monthly"}
RANGE_DAYS = {"30d": 30, "90d": 90, "180d": 180, "365d": 365}
RANGE_LABEL = {"30d": "30 days", "90d": "90 days", "180d": "180 days", "365d": "1 year"}
COMPUTE = (DeviceType.workstation, DeviceType.server)

_PATTERNS = (
    ("windows", ("windows",)),
    ("macos", ("mac os", "macos", "os x", "darwin")),
    ("network", ("cisco", "fortios", "fortinet", "junos", "juniper", "pan-os", "palo alto", "arista", "mikrotik", "sonicwall")),
    ("linux", ("linux", "rhel", "red hat", "ubuntu", "centos", "debian", "suse", "amazon", "rocky", "alma", "fedora")),
    ("mobile", ("ios", "ipados", "android")),
    ("hypervisor", ("esx", "vmware", "hyper-v")),
    ("unix", ("aix", "solaris", "hp-ux", "freebsd", "openbsd", "unix")),
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def os_family():
    """The device's OS family from its OS string. Order matters: "Cisco IOS" is network, not mobile."""
    o = func.lower(func.coalesce(Device.os, ""))
    return case((o == "", "unknown"), *[(or_(*(o.like(f"%{p}%") for p in pats)), fam) for fam, pats in _PATTERNS],
                else_="other")


def has_scanner():
    from api.grc.checks import SCANNERS
    srcs = func.coalesce(Device.sources, "")
    return or_(*(srcs.like(f"%,{s},%") for s in SCANNERS))


def has_edr():
    return Device.edr_active.is_(True)


def active(days: int = 30):
    cut = now() - timedelta(days=days)
    return or_(Device.last_seen >= cut, Device.edr_last_seen >= cut, Device.ad_last_logon >= cut)


def cloud_ids():
    from api.models.cloud import CloudAsset
    return select(CloudAsset.device_id).where(CloudAsset.device_id.is_not(None))


def scoped(ctx) -> list:
    return [] if ctx.scope is None else [ctx.scope]


def fleet_only(ctx) -> dict | None:
    """Snapshots are fleet-wide numbers, so people limited to some devices don't get them."""
    if ctx.scope is not None:
        return {"error": "This trend covers every device, so it's for people who can see every device."}
    return None


async def snaps(db, keys: list[str], days: int) -> tuple[list[str], dict[str, list]]:
    """Daily snapshot values for the last `days` days, None where a day wasn't recorded."""
    from api.models.snapshot import MetricSnapshot
    start = date.today() - timedelta(days=days - 1)
    rows = (await db.execute(select(MetricSnapshot.key, MetricSnapshot.day, MetricSnapshot.value)
                             .where(MetricSnapshot.key.in_(keys), MetricSnapshot.day >= start))).all()
    x = [(start + timedelta(days=i)).isoformat() for i in range(days)]
    grid = {k: dict.fromkeys(x) for k in keys}
    for k, d, v in rows:
        if d.isoformat() in grid[k]:
            grid[k][d.isoformat()] = v
    return x, {k: list(g.values()) for k, g in grid.items()}


async def snap_on(db, key: str, day: date) -> int | None:
    """The value recorded on that day or the closest day before it, within a week."""
    from api.models.snapshot import MetricSnapshot
    return (await db.execute(select(MetricSnapshot.value).where(
        MetricSnapshot.key == key, MetricSnapshot.day <= day, MetricSnapshot.day > day - timedelta(days=7))
        .order_by(MetricSnapshot.day.desc()).limit(1))).scalar_one_or_none()


def _key(d: date, unit: str) -> str:
    if unit == "week":
        return (d - timedelta(days=d.weekday())).isoformat()
    if unit == "month":
        return d.isoformat()[:7]
    return d.isoformat()


def resample(x: list[str], series: list[list], unit: str, how: list[str]) -> tuple[list[str], list[list]]:
    """Daily points into weeks or months. how per series: "last" for levels (open count), "sum" for flows
    (new per day), "avg" for rates. Empty days (None) are skipped."""
    if unit == "day":
        return x, series
    labels: list[str] = []
    idx: dict[str, int] = {}
    for d in x:
        k = _key(date.fromisoformat(d), unit)
        if k not in idx:
            idx[k] = len(labels)
            labels.append(k)
    out = []
    for s, h in zip(series, how):
        vals: list[list] = [[] for _ in labels]
        for d, v in zip(x, s):
            if v is not None:
                vals[idx[_key(date.fromisoformat(d), unit)]].append(v)
        if h == "sum":
            out.append([sum(v) if v else None for v in vals])
        elif h == "avg":
            out.append([round(sum(v) / len(v), 1) if v else None for v in vals])
        else:
            out.append([v[-1] if v else None for v in vals])
    return labels, out


def change(daily: list, what: str, days: int = 30) -> str | None:
    """'12.4% decrease in open findings over the last month', from a daily series (last value vs `days` ago)."""
    vals = [v for v in daily if v is not None]
    if len(daily) <= days or not vals:
        return None
    then, cur = daily[-days - 1], vals[-1]
    if not then:
        return None
    pct = (cur - then) / then * 100
    if abs(pct) < 0.05:
        return f"No change in {what} over the last month"
    return f"{abs(pct):.1f}% {'increase' if pct > 0 else 'decrease'} in {what} over the last month"


def delta(cur, was, better: str = "down") -> dict | None:
    """A KPI's change against an earlier value. better: which direction is good news."""
    if cur is None or not was:
        return None
    return {"pct": round((cur - was) / was * 100, 1), "was": was, "better": better}
