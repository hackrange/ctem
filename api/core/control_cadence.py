"""How often each control must be tested (GRC > Controls > Testing rules, admins).

A control's interval is, first match wins: its own override; its FairTPRM frequency (monthly, quarterly...) when
"use the control's frequency" is on; its risk level; the default. Its next test is due that many days after its
last test (a CTEM attestation, or FairTPRM's last tested date when there is no attestation yet); a control never
tested is due now."""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

KEY = "grc_test_cadence"
RISKS = ("critical", "high", "medium", "low")
FREQUENCY_DAYS = {"daily": 1, "weekly": 7, "monthly": 30, "quarterly": 90, "semi_annual": 182, "semiannual": 182,
                  "semi-annually": 182, "annual": 365, "annually": 365, "yearly": 365}
DEFAULTS = {"by_risk": {"critical": 30, "high": 90, "medium": 180, "low": 365}, "default_days": 365,
            "use_control_frequency": True, "controls": {}}
LIMITS = (1, 3650)


def _days(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and LIMITS[0] <= v <= LIMITS[1] else None


def clean(raw) -> dict:
    out = json.loads(json.dumps(DEFAULTS))
    if not isinstance(raw, dict):
        return out
    for r in RISKS:
        d = _days((raw.get("by_risk") or {}).get(r))
        if d:
            out["by_risk"][r] = d
    out["default_days"] = _days(raw.get("default_days")) or out["default_days"]
    out["use_control_frequency"] = bool(raw.get("use_control_frequency", True))
    out["controls"] = {str(k)[:36]: d for k, v in (raw.get("controls") or {}).items() if (d := _days(v))}
    return out


async def load(db: AsyncSession) -> dict:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    try:
        return clean(json.loads(row.value)) if row and row.value else clean(None)
    except ValueError:
        return clean(None)


async def save(db: AsyncSession, raw: dict) -> dict:
    from api.models.settings import AppSetting
    good = clean(raw)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=KEY, value=json.dumps(good)))
    else:
        row.value = json.dumps(good)
    await db.flush()
    return good


def interval(rules: dict, control) -> tuple[int, str]:
    """(days, why) for one control."""
    own = rules["controls"].get(str(control.id))
    if own:
        return own, "set for this control"
    freq = (control.frequency or "").strip().lower().replace(" ", "_")
    if rules["use_control_frequency"] and freq in FREQUENCY_DAYS:
        return FREQUENCY_DAYS[freq], f"the control's frequency ({control.frequency})"
    risk = (control.risk_level or "").strip().lower()
    if risk in rules["by_risk"]:
        return rules["by_risk"][risk], f"{risk} risk"
    return rules["default_days"], "the default"


def _day(dt) -> date | None:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).date()
    return dt


def due(rules: dict, control, last_tested) -> dict:
    """When the next test is due and whether it's overdue."""
    days, why = interval(rules, control)
    last = _day(last_tested)
    nxt = last + timedelta(days=days) if last else None
    today = datetime.now(timezone.utc).date()
    return {"interval_days": days, "interval_why": why, "last_tested": last.isoformat() if last else None,
            "next_due": nxt.isoformat() if nxt else None, "overdue": nxt is None or nxt < today,
            "days_left": (nxt - today).days if nxt else None}
