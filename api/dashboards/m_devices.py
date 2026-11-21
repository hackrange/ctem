"""Device and EDR widgets, limited to the devices the viewer may see."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select

from api.dashboards.catalog import Metric, Param, metric
from api.models.device import Device, DeviceAssignment, DeviceType, RiskGrade

DTYPE = Param("device_type", "Device type", ("any", *DeviceType.__members__), labels={"any": "All device types"})
STATUS = ("all", "contained", "hidden_in_edr", "out_of_scope", "no_edr", "stale_30d", "internet_exposed", "kev")
STATUS_LABEL = {"all": "All devices", "contained": "Contained by the EDR", "hidden_in_edr": "Hidden in the EDR console",
                "out_of_scope": "Not in scope", "no_edr": "Workstations and servers without EDR",
                "stale_30d": "Not seen for 30 days", "internet_exposed": "Internet exposed", "kev": "With KEV findings"}
STATUS_HREF = {"contained": "/devices?status=contained", "hidden_in_edr": "/devices?status=edr_hidden",
               "out_of_scope": "/devices?status=out_of_scope"}
GRADE_COLOR = {"A": "--severity-info", "B": "--severity-low", "C": "--severity-medium", "D": "--severity-high", "F": "--severity-critical"}


def _now():
    return datetime.now(timezone.utc)


def _base(ctx, p) -> list:
    w = [] if ctx.scope is None else [ctx.scope]
    if p.get("device_type") in DeviceType.__members__:
        w.append(Device.device_type == DeviceType[p["device_type"]])
    return w


def _status(s: str):
    now = _now()
    if s == "contained":
        return Device.edr_contained.is_(True)
    if s == "hidden_in_edr":
        return Device.edr_hidden.is_(True)
    if s == "out_of_scope":
        return Device.scope_exempt_until > now
    if s == "no_edr":
        return (Device.edr_active.is_(False)) & Device.device_type.in_([DeviceType.workstation, DeviceType.server])
    if s == "stale_30d":
        cut = now - timedelta(days=30)
        return ~or_(Device.last_seen >= cut, Device.edr_last_seen >= cut, Device.ad_last_logon >= cut)
    if s == "internet_exposed":
        return Device.is_internet_exposed.is_(True)
    if s == "kev":
        return Device.kev_findings > 0
    return None


async def _count(ctx, p):
    w = _base(ctx, p)
    cond = _status(p["status"])
    if cond is not None:
        w.append(cond)
    n = (await ctx.db.execute(select(func.count()).select_from(Device).where(*w))).scalar_one()
    return {"value": n, "note": STATUS_LABEL[p["status"]], "href": STATUS_HREF.get(p["status"], "/devices")}


async def _edr(ctx, p):
    """Share of workstations and servers seen in the last 30 days that have a working EDR sensor."""
    cut = _now() - timedelta(days=30)
    w = [*_base(ctx, {}), Device.device_type.in_([DeviceType.workstation, DeviceType.server]),
         or_(Device.last_seen >= cut, Device.edr_last_seen >= cut, Device.ad_last_logon >= cut)]
    total, on = (await ctx.db.execute(select(func.count(), func.count().filter(Device.edr_active.is_(True)))
                                      .select_from(Device).where(*w))).one()
    return {"value": round(100 * on / total, 1) if total else None, "unit": "%",
            "note": f"{on:,} of {total:,} active workstations and servers", "href": "/grc/checks/ctem_edr_coverage"}


async def _by_type(ctx, p):
    rows = (await ctx.db.execute(select(Device.device_type, func.count()).where(*_base(ctx, {}))
                                 .group_by(Device.device_type).order_by(func.count().desc()))).all()
    return {"items": [{"name": (t.value if t else "unknown").replace("_", " "), "value": n,
                       "href": f"/devices?device_type={t.value}" if t else None} for t, n in rows]}


async def _by_grade(ctx, p):
    rows = (await ctx.db.execute(select(Device.risk_grade, func.count()).where(*_base(ctx, p))
                                 .group_by(Device.risk_grade))).all()
    order = {g.value: i for i, g in enumerate(RiskGrade)}
    rows = sorted(rows, key=lambda r: order.get(r[0].value if r[0] else "", 99))
    return {"items": [{"name": f"Grade {g.value}" if g else "Not scored", "value": n,
                       "href": f"/devices?grade={g.value if g else 'NONE'}", "color": GRADE_COLOR.get(g.value if g else "")}
                      for g, n in rows]}


async def _inventory(ctx, p):
    w = _base(ctx, p)
    rows = (await ctx.db.execute(select(DeviceAssignment.status, func.count()).join(Device, Device.id == DeviceAssignment.device_id)
                                 .where(DeviceAssignment.status.is_not(None), *w).group_by(DeviceAssignment.status))).all()
    return {"items": [{"name": (s or "").replace("_", " "), "value": n, "href": f"/devices?status={s}"} for s, n in rows]}


async def _riskiest(ctx, p):
    w = _base(ctx, p)
    rows = (await ctx.db.execute(select(Device.id, Device.hostname, Device.risk_grade, Device.risk_score, Device.open_findings,
                                        Device.kev_findings).where(*w).order_by(Device.risk_score.desc().nulls_last())
                                 .limit(p["limit"]))).all()
    from api.routes import device_query as dq
    return {"columns": ["Device", "Grade", "Score", "Open", "KEV"],
            "rows": [[dq.short_name(h), g.value if g else None, round(s) if s is not None else None, o, k] for _, h, g, s, o, k in rows],
            "hrefs": [f"/devices/{i}" for i, *_ in rows]}


C = "Devices and EDR"
metric(Metric("devices.count", "Device count", C, "value",
              (Param("status", "Which devices", STATUS, labels=STATUS_LABEL), DTYPE), _count,
              "How many devices: all, contained, hidden in the EDR, not in scope, without EDR, stale, exposed."))
metric(Metric("devices.edr_coverage", "EDR coverage", C, "value", (), _edr,
              "Share of recently seen workstations and servers with a working EDR sensor."))
metric(Metric("devices.by_type", "Devices by type", C, "parts", (), _by_type))
metric(Metric("devices.by_grade", "Devices by risk grade", C, "parts", (DTYPE,), _by_grade))
metric(Metric("devices.inventory_status", "Inventory status", C, "parts", (DTYPE,), _inventory,
              "Devices marked shipped, lost, stolen or returned."))
metric(Metric("devices.riskiest", "Riskiest devices", C, "table", (Param("limit", "Rows", low=3, high=25, default=10), DTYPE),
              _riskiest))
