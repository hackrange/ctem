"""Operations control: is the security monitoring itself running (sources syncing, shippers checking in)?"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import Check, Outcome, Threshold, aware, grade_low, now, register
from api.models.collector import CollectorProfile, CollectorToken
from api.models.integration import IntegrationConfig, SyncJob, SyncStatus

_NOT_TELEMETRY = {"ai", "anthropic", "openai", "custom_ai", "servicenow"}


async def _health(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    cfgs = [c for c in (await db.execute(select(IntegrationConfig).where(IntegrationConfig.is_enabled == True))).scalars()  # noqa: E712
            if c.vendor.value not in _NOT_TELEMETRY]
    last_ok = dict((await db.execute(select(SyncJob.integration_id, func.max(SyncJob.finished_at))
                                     .where(SyncJob.status == SyncStatus.success).group_by(SyncJob.integration_id))).all())
    cut = now() - timedelta(hours=t["source_hours"])
    rows, stale = [], 0
    for c in cfgs:
        ok = aware(last_ok.get(str(c.id)))
        bad = ok is None or ok < cut
        stale += bad
        rows.append({"kind": "integration", "name": c.name, "type": c.vendor.value,
                     "last_success": ok.isoformat() if ok else "never", "healthy": not bad})
    ship_cut = now() - timedelta(minutes=t["shipper_minutes"])
    shippers = (await db.execute(select(CollectorToken, CollectorProfile.name).join(
        CollectorProfile, CollectorProfile.id == CollectorToken.profile_id).where(CollectorToken.is_active == True))).all()  # noqa: E712
    for tok, name in shippers:
        seen = aware(tok.last_seen)
        bad = seen is None or seen < ship_cut
        stale += bad
        rows.append({"kind": "shipper", "name": name, "type": "on-prem shipper",
                     "last_success": seen.isoformat() if seen else "never", "healthy": not bad})
    if not rows:
        return Outcome("error", "no telemetry sources are configured")
    out = Outcome(grade_low(stale, 0, t["warn_max"]),
                  f"{len(rows) - stale} of {len(rows)} telemetry sources are current "
                  f"({len(cfgs)} integrations, {len(shippers)} shippers)",
                  {"sources": len(rows), "stale": stale, "integrations": len(cfgs), "shippers": len(shippers)})
    if detail:
        out.columns, out.rows = ["kind", "name", "type", "last_success", "healthy"], rows
    return out


register(Check(
    "ctem_monitoring_health", "Security monitoring operating", "Every telemetry source synced recently; every shipper checking in",
    1, (), ("NIST CSF DE.CM-01", "SOC 2 CC7.1", "ISO 27001 A.8.16"),
    {"source_hours": Threshold(26, 1, 720, "a source with no successful sync for this long is stale"),
     "shipper_minutes": Threshold(120, 15, 10080, "a shipper silent this long is stale"),
     "warn_max": Threshold(1, 0, 1000, "stale sources tolerated as a warning")}, _health))
