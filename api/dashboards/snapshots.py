"""Daily fleet snapshots for trends the data can't rebuild by itself: the risk score, assets by their worst open
severity, accepted risk, and EDR and scanner coverage. Recorded hourly (today's row is overwritten), so the
lines fill in from the day CTEM starts recording. Open findings, new and fixed are rebuilt from finding dates
instead and need no snapshot.

Keys (all integers): risk_avg_x10, assets_total, assets_cloud, assets_active, worst_<severity>, accepted_findings,
accepted_risk_pct_x10, cov_eligible, cov_edr, cov_scanner."""
from __future__ import annotations

from datetime import date

from sqlalchemy import Float, and_, case, cast, func, select

from api.dashboards import fleet
from api.models.device import Device
from api.models.snapshot import MetricSnapshot
from api.models.vuln import Finding, FindingStatus, Vulnerability

OPEN = (FindingStatus.open, FindingStatus.in_progress)
SEVERITIES = ("critical", "high", "medium", "low")
HEAVY = ("worst_critical", "accepted_risk_pct_x10")   # big scans: once a day is enough


async def _have_today(db, key: str) -> bool:
    return (await db.execute(select(func.count()).select_from(MetricSnapshot).where(
        MetricSnapshot.key == key, MetricSnapshot.day == date.today()))).scalar_one() > 0


async def fleet_values(db, heavy: bool) -> dict[str, int]:
    out: dict[str, int] = {}
    avg = (await db.execute(select(func.avg(Device.risk_score)).where(Device.risk_score.is_not(None)))).scalar_one()
    out["risk_avg_x10"] = round(float(avg or 0) * 10)
    total, cloud, act = (await db.execute(select(
        func.count(), func.count().filter(Device.id.in_(fleet.cloud_ids())), func.count().filter(fleet.active())
    ).select_from(Device))).one()
    out.update(assets_total=total, assets_cloud=cloud, assets_active=act)
    elig, edr, scan = (await db.execute(select(
        func.count(), func.count().filter(fleet.has_edr()), func.count().filter(fleet.has_scanner()))
        .select_from(Device).where(Device.device_type.in_(fleet.COMPUTE), fleet.active()))).one()
    out.update(cov_eligible=elig, cov_edr=edr, cov_scanner=scan)
    out["accepted_findings"] = (await db.execute(select(func.count()).select_from(Finding).where(
        Finding.status.in_(OPEN), Finding.exception_id.is_not(None)))).scalar_one()
    if heavy:
        c = Vulnerability.cvss_base
        worst = (select(Finding.device_id, func.max(func.coalesce(c, 0)).label("m"))
                 .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                 .where(Finding.status.in_(OPEN)).group_by(Finding.device_id).subquery())
        sev = case((worst.c.m >= 9, "critical"), (worst.c.m >= 7, "high"), (worst.c.m >= 4, "medium"), else_="low")
        counts = dict((await db.execute(select(sev, func.count()).select_from(worst).group_by(sev))).all())
        out.update({f"worst_{s}": counts.get(s, 0) for s in SEVERITIES})
        score = func.coalesce(Finding.composite_score, cast(0, Float))
        allr, acc = (await db.execute(select(func.sum(score), func.sum(score).filter(Finding.exception_id.is_not(None)))
                                      .where(and_(Finding.status.in_(OPEN))))).one()
        out["accepted_risk_pct_x10"] = round(1000 * float(acc or 0) / float(allr)) if allr else 0
    return out


async def record(db) -> int:
    heavy = not await _have_today(db, HEAVY[0])
    vals = await fleet_values(db, heavy)
    today = date.today()
    for k, v in vals.items():
        await db.merge(MetricSnapshot(key=k, day=today, value=int(v)))
    await db.commit()
    return len(vals)
