"""An asset's trend: open findings per day (all, critical, high) and its daily risk score, for the sparkline in
the Details panel and the chart it opens. Built from the asset's own findings (first found and last seen), so it
covers any range from day one; the score comes from the score history where there is some."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.risk import RiskScoreHistory
from api.models.user import User
from api.models.vuln import Finding, FindingStatus, Vulnerability

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])
OPEN = {FindingStatus.open, FindingStatus.in_progress}


def _day(dt: datetime | None) -> date | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).date()


def series(rows, start: date, end: date) -> dict:
    """rows: (first found, last seen, status, cvss). A finding counts as open from the day it was first found until
    the day before its last sighting when it was fixed, or until today when it is still open. Findings accepted
    as a risk or marked false positive drop out."""
    n = (end - start).days + 1
    diff = {k: [0] * (n + 1) for k in ("open", "critical", "high")}
    for first, last, status, cvss in rows:
        f = _day(first)
        if f is None or f > end:
            continue
        if status in OPEN:
            stop = end
        elif status == FindingStatus.remediated:
            stop = (_day(last) or f) - timedelta(days=1)
        else:
            continue
        lo, hi = max(f, start), min(stop, end)
        if hi < lo:
            continue
        a, b = (lo - start).days, (hi - start).days + 1
        keys = ["open"] + (["critical"] if (cvss or 0) >= 9 else ["high"] if (cvss or 0) >= 7 else [])
        for k in keys:
            diff[k][a] += 1
            diff[k][b] -= 1
    out = {}
    for k, d in diff.items():
        run, vals = 0, []
        for i in range(n):
            run += d[i]
            vals.append(run)
        out[k] = vals
    return {"days": [(start + timedelta(days=i)).isoformat() for i in range(n)], **out}


@router.get("/{device_id}/trend")
async def device_trend(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices", "read")),
    _findings: User = Depends(require_permission("findings", "read")),   # inventory sees devices, not vulns
    db: AsyncSession = Depends(get_session),
    days: int = Query(30, ge=7, le=365),
):
    from api.routes.devices import _visible_device
    device = await _visible_device(device_id, current_user, db)   # 404 for absent and not yours alike
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days - 1)
    rows = (await db.execute(
        select(Finding.first_detected, Finding.last_seen, Finding.status, Vulnerability.cvss_base)
        .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(Finding.device_id == device.id, Finding.first_detected.is_not(None)))).all()
    out = series(rows, start, end)
    hist = (await db.execute(
        select(RiskScoreHistory.recorded_at, RiskScoreHistory.score)
        .where(RiskScoreHistory.entity_type == "device", RiskScoreHistory.entity_id == str(device.id),
               RiskScoreHistory.recorded_at >= datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc))
        .order_by(RiskScoreHistory.recorded_at))).all()
    by_day = {}
    for at, score in hist:
        by_day[_day(at).isoformat()] = round(float(score), 1)   # the day's last score
    out["score"] = [by_day.get(d) for d in out["days"]]
    out["range_days"] = days
    return out
