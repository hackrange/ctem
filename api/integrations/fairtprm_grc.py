"""Pull FairTPRM's GRC module: frameworks + compliance, controls, risk register, evidence, monitors, dashboard.

FairTPRM is the source of truth, so each table mirrors it: rows that vanish there are removed here,
but only after that resource was fetched successfully. All calls are GETs.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.grc import GrcControl, GrcEvidence, GrcFramework, GrcMonitor, GrcRisk

log = logging.getLogger("open-ctem.fairtprm")
DASHBOARD_SETTING = "grc_dashboard_fairtprm"


def _dt(val):
    from api.integrations.fairtprm import _parse_dt
    return _parse_dt(val)


def _date(val):
    dt = _dt(val)
    return dt.date() if dt else None


def _num(val) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _int(val) -> int:
    n = _num(val)
    return int(n) if n is not None else 0


def _text(val, cap: int) -> str | None:
    return str(val)[:cap] if val not in (None, "") else None


def _ids(val) -> list[str]:
    """control_ids arrive as a JSON string, a list, a comma list, or nothing."""
    if val in (None, ""):
        return []
    if isinstance(val, str):
        try:
            val = json.loads(val)
        except ValueError:
            val = val.split(",")
    if not isinstance(val, list):
        val = [val]
    return [str(v).strip() for v in val if str(v).strip().isdigit()][:500]


def _codes(val) -> list[str]:
    if isinstance(val, list):
        return [str(v)[:50] for v in val][:50]
    return [c.strip()[:50] for c in str(val or "").split(",") if c.strip()][:50]


async def _mirror(db: AsyncSession, model, rows: list[dict], fill) -> int:
    now = datetime.now(timezone.utc)
    existing = {r.external_id: r for r in (await db.execute(select(model).where(model.source == "fairtprm"))).scalars()}
    seen = set()
    for raw in rows:
        if not isinstance(raw, dict) or raw.get("id") is None:
            continue
        ext = str(raw["id"])
        rec = existing.get(ext)
        if rec is None:
            rec = model(source="fairtprm", external_id=ext)
            db.add(rec)
            existing[ext] = rec
        fill(rec, raw)
        rec.synced_at = now
        seen.add(ext)
    gone = set(existing) - seen
    if gone:
        await db.execute(delete(model).where(model.source == "fairtprm", model.external_id.in_(gone)))
    return len(seen)


def _framework(dash: dict):
    by_id = {str(f.get("framework_id")): f for f in (dash.get("frameworks") or []) if isinstance(f, dict)}

    def fill(rec: GrcFramework, f: dict) -> None:
        rec.code = str(f.get("code") or "")[:50] or f"FW-{f['id']}"
        rec.name = str(f.get("name") or rec.code)[:255]
        rec.version = _text(f.get("version"), 50)
        rec.is_active = bool(_int(f.get("is_active", 1)))
        rec.compliance_year = _int(f.get("compliance_year")) or None
        s = by_id.get(str(f["id"]), {})
        rec.total_requirements = _int(s.get("total_requirements"))
        rec.implemented = _int(s.get("fully_implemented"))
        rec.partial = _int(s.get("partially_implemented"))
        rec.in_progress = _int(s.get("in_progress"))
        rec.planned = _int(s.get("planned"))
        rec.not_applicable = _int(s.get("not_applicable"))
        rec.compliance_percentage = _num(s.get("compliance_percentage"))
    return fill


def _control(rec: GrcControl, c: dict) -> None:
    rec.control_ref = _text(c.get("control_ref"), 50)
    rec.title = str(c.get("title") or rec.control_ref or "Untitled control")[:500]
    for f, cap in (("control_type", 32), ("control_category", 32), ("implementation_status", 32),
                   ("effectiveness", 32), ("risk_level", 16), ("frequency", 16)):
        setattr(rec, f, _text(c.get(f), cap))
    rec.last_tested_at = _dt(c.get("last_tested_at"))
    rec.evidence_count = _int(c.get("evidence_count"))
    rec.mapped_requirements = _int(c.get("mapped_requirements"))
    rec.frameworks = _codes(c.get("frameworks"))
    rec.is_active = bool(_int(c.get("is_active", 1)))


def _risk(rec: GrcRisk, r: dict) -> None:
    rec.risk_ref = _text(r.get("risk_ref"), 50)
    rec.title = str(r.get("title") or rec.risk_ref or "Untitled risk")[:500]
    rec.description = _text(r.get("description"), 20000)
    for f, cap in (("risk_category", 32), ("likelihood", 32), ("impact", 32), ("risk_treatment", 16), ("status", 16)):
        setattr(rec, f, _text(r.get(f), cap))
    rec.inherent_risk_score = _num(r.get("inherent_risk_score"))
    rec.residual_risk_score = _num(r.get("residual_risk_score"))
    rec.control_ids = _ids(r.get("control_ids"))
    rec.vendor_id = str(r["vendor_id"])[:64] if r.get("vendor_id") not in (None, "", 0) else None
    rec.review_date = _date(r.get("review_date"))


def _evidence(rec: GrcEvidence, e: dict) -> None:
    rec.evidence_ref = _text(e.get("evidence_ref"), 50)
    rec.title = str(e.get("title") or rec.evidence_ref or "Evidence")[:500]
    for f, cap in (("evidence_type", 32), ("collection_method", 16), ("status", 16)):
        setattr(rec, f, _text(e.get(f), cap))
    rec.collected_at = _dt(e.get("collected_at"))
    rec.valid_until = _dt(e.get("valid_until"))
    rec.control_ids = _ids(e.get("control_ids"))


def _monitor(rec: GrcMonitor, m: dict) -> None:
    rec.name = str(m.get("name") or m.get("monitor_ref") or "Monitor")[:255]
    rec.check_type = _text(m.get("check_type"), 100)
    rec.collector_class = _text(m.get("collector_class"), 255)
    rec.frequency = _text(m.get("frequency"), 16)
    rec.is_enabled = bool(_int(m.get("is_enabled", 1)))
    rec.last_result = _text(m.get("last_result"), 16)
    rec.last_run_at = _dt(m.get("last_run_at"))
    rec.control_ids = _ids(m.get("control_ids"))


async def _save_dashboard(db: AsyncSession, dash: dict) -> None:
    from api.models.settings import AppSetting
    keep = {k: v for k, v in dash.items() if k != "frameworks"}
    keep["synced_at"] = datetime.now(timezone.utc).isoformat()
    row = (await db.execute(select(AppSetting).where(AppSetting.key == DASHBOARD_SETTING))).scalar_one_or_none()
    if row is None:
        row = AppSetting(key=DASHBOARD_SETTING, is_sensitive=False)
        db.add(row)
    row.value = json.dumps(keep, default=str)


async def sync_grc(conn, client, db: AsyncSession) -> tuple[int, list[str]]:
    """Returns (records mirrored, problems). A failed resource leaves its old rows untouched."""
    from api.integrations.fairtprm import FairTPRMError

    count, problems = 0, []

    async def fetch(path: str):
        try:
            return (await conn._get(client, path)).get("data")
        except FairTPRMError as exc:
            problems.append(f"{path}: {exc}")
            return None

    dash = await fetch("/grc/dashboard")
    if isinstance(dash, dict):
        await _save_dashboard(db, dash)
    frameworks = await fetch("/grc/frameworks")
    if isinstance(frameworks, list):
        count += await _mirror(db, GrcFramework, frameworks, _framework(dash if isinstance(dash, dict) else {}))
    for path, model, fill in (("/grc/controls", GrcControl, _control), ("/grc/risks", GrcRisk, _risk),
                              ("/grc/evidence?limit=200", GrcEvidence, _evidence), ("/grc/monitors", GrcMonitor, _monitor)):
        rows = await fetch(path)
        if isinstance(rows, list):
            count += await _mirror(db, model, rows, fill)
    await db.commit()
    log.info("FairTPRM GRC: %d records mirrored, %d problems", count, len(problems))
    return count, problems
