"""Remediation SLAs (days to fix, by severity): one setting for the whole install.

Admins change them from Vulnerabilities > Change SLAs. They drive finding age colors and past-SLA flags, the
Vulnerability Dashboard's past-SLA count and aging, and the defaults of the remediation SLA control check (a curated
rule that sets that check's own days still wins). Loaded at most once a minute per process; a save applies at once
in the process that saved it and within a minute everywhere else."""
from __future__ import annotations

import json
import logging
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)
KEY = "vuln_sla_days"
DEFAULTS = {"critical": 15, "high": 30, "medium": 90, "low": 180}
LIMITS = (1, 365)
_TTL = 60.0
_state = {"at": 0.0}


def clean(raw) -> dict[str, int]:
    """Whole days within LIMITS for each severity; anything else keeps the default. Raises ValueError on bad input
    when strict values are given (see validate)."""
    out = dict(DEFAULTS)
    if isinstance(raw, dict):
        for k in DEFAULTS:
            v = raw.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and LIMITS[0] <= v <= LIMITS[1]:
                out[k] = v
    return out


def validate(values: dict) -> dict[str, int]:
    out = clean(values)
    if not out["critical"] <= out["high"] <= out["medium"] <= out["low"]:
        raise ValueError("Each SLA must be no longer than the next lower severity's (critical <= high <= medium <= low)")
    return out


def _apply(values: dict[str, int]) -> None:
    """Update the values every part of CTEM reads, in place."""
    from api.core.vuln_dashboard import SLA_DAYS
    SLA_DAYS.update(values)
    try:
        from api.grc.checks import REGISTRY
        import api.grc.checks.vulns  # noqa: F401 -- registers the SLA check
        c = REGISTRY.get("ctem_vuln_sla")
        if c:
            c.thresholds["critical_days"].default = values["critical"]
            c.thresholds["high_days"].default = values["high"]
    except Exception:  # noqa: BLE001 -- the check keeps its last defaults
        log.warning("SLA check defaults not updated")


def current() -> dict[str, int]:
    from api.core.vuln_dashboard import SLA_DAYS
    return {k: SLA_DAYS.get(k, d) for k, d in DEFAULTS.items()}


async def load(db: AsyncSession, force: bool = False) -> dict[str, int]:
    if not force and time.monotonic() - _state["at"] < _TTL:
        return current()
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    try:
        values = clean(json.loads(row.value)) if row and row.value else dict(DEFAULTS)
    except ValueError:
        values = dict(DEFAULTS)
    _apply(values)
    _state["at"] = time.monotonic()
    return values


def fresh_dependency():
    """Route dependency: the current SLAs before the route reads any age (same session as the route)."""
    from fastapi import Depends

    from api.core.db import get_session

    async def dep(db: AsyncSession = Depends(get_session)) -> None:
        await load(db)
    return dep


fresh = fresh_dependency()


async def save(db: AsyncSession, values: dict) -> dict[str, int]:
    from api.models.settings import AppSetting
    good = validate(values)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=KEY, value=json.dumps(good)))
    else:
        row.value = json.dumps(good)
    await db.flush()
    _apply(good)
    _state["at"] = time.monotonic()
    return good
