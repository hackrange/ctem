"""Control checks CTEM answers for FairTPRM's continuous monitors.

Each check measures one control from data CTEM already holds and returns pass / warning /
fail / error in the shape FairTPRM's evidence collectors use. Two rules hold everywhere:
stale or missing source data is an error, never a pass; and the summary result carries
counts only, so nothing personal lands in FairTPRM's plain-text evidence column.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.integration import IntegrationConfig, SyncJob, SyncStatus

EDR = ("crowdstrike", "sentinelone", "msdefender", "tanium", "cortex_xdr")
SCANNERS = ("qualys", "rapid7_insightvm", "tanium", "msdefender")
EXPOSURE = SCANNERS + ("rapid7_appsec",)   # web app scanners see internet-facing apps too
DIRECTORY = ("ldap",)
IDENTITY = ("grip",)
SHADOW = ("grip", "fairtprm:shadow_saas")   # Grip here, or FairTPRM's Grip/HERO-fed inventory
PENTEST = ("horizon3",)
HARDENING = ("crowdstrike",)


@dataclass
class Outcome:
    result: str                 # pass | warning | fail | error
    summary: str
    details: dict = field(default_factory=dict)
    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)


@dataclass
class Threshold:
    default: int
    lo: int
    hi: int
    help: str


@dataclass
class Check:
    check_type: str
    name: str
    description: str
    version: int
    sources: tuple[str, ...]          # integration vendors; any one fresh is enough
    controls: tuple[str, ...]         # suggested mappings for the FairTPRM monitor
    thresholds: dict[str, Threshold]
    run: Callable[[AsyncSession, dict, bool], Awaitable[Outcome]]
    max_age_hours: int = 48
    device_scoped: bool = False       # curated rules may narrow which devices it counts

    def parse(self, params: dict) -> dict:
        """Only declared thresholds, only integers, only inside their bounds."""
        unknown = set(params) - set(self.thresholds)
        if unknown:
            raise ValueError(f"unknown parameter: {sorted(unknown)[0]}")
        out = {}
        for name, t in self.thresholds.items():
            raw = params.get(name)
            if raw is None:
                out[name] = t.default
                continue
            try:
                val = int(raw)
            except (TypeError, ValueError):
                raise ValueError(f"{name} must be an integer") from None
            if not t.lo <= val <= t.hi:
                raise ValueError(f"{name} must be between {t.lo} and {t.hi}")
            out[name] = val
        return out

    def catalog(self) -> dict:
        return {"check_type": self.check_type, "name": self.name, "description": self.description,
                "check_version": self.version, "data_sources": list(self.sources),
                "suggested_controls": list(self.controls),
                "thresholds": {k: {"default": t.default, "min": t.lo, "max": t.hi, "help": t.help}
                               for k, t in self.thresholds.items()}, "device_scoped": self.device_scoped}


REGISTRY: dict[str, Check] = {}


def register(check: Check) -> Check:
    REGISTRY[check.check_type] = check
    return check


def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def pct(part: int, whole: int) -> float:
    return round(part * 100.0 / whole, 1) if whole else 100.0


def grade_high(value: float, pass_at: float, warn_at: float) -> str:
    """Bigger is better (coverage percentages)."""
    return "pass" if value >= pass_at else "warning" if value >= warn_at else "fail"


def grade_low(value: float, pass_max: float, warn_max: float) -> str:
    """Smaller is better (counts of bad things)."""
    return "pass" if value <= pass_max else "warning" if value <= warn_max else "fail"


async def freshness(db: AsyncSession, vendors: tuple[str, ...], max_age_hours: int) -> tuple[bool, dict, str]:
    """Latest successful sync per configured source. Fresh when at least one is inside the window."""
    if not vendors:
        return True, {}, ""
    # "fairtprm:shadow_saas" is part of the FairTPRM integration, fresh only when that data actually arrived
    enabled = {c.vendor.value for c in (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.is_enabled == True))).scalars()}  # noqa: E712
    configured = {v for v in vendors if v.split(":", 1)[0] in enabled}
    if not configured:
        return False, {}, f"no data source configured (needs one of: {', '.join(vendors)})"
    rows = await db.execute(select(SyncJob.vendor, func.max(SyncJob.finished_at)).where(
        SyncJob.vendor.in_(configured), SyncJob.status == SyncStatus.success).group_by(SyncJob.vendor))
    seen = {v: aware(ts) for v, ts in rows.all()}
    stamps = {v: (seen[v].isoformat() if seen.get(v) else None) for v in sorted(configured)}
    cutoff = now() - timedelta(hours=max_age_hours)
    if any(ts and ts >= cutoff for ts in seen.values()):
        return True, stamps, ""
    if not any(seen.values()):
        return False, stamps, f"no successful sync yet from: {', '.join(sorted(configured))}"
    return False, stamps, f"source data is older than {max_age_hours}h, so the result can't be trusted"


async def evaluate(db: AsyncSession, check: Check, params: dict, detail: bool = False,
                   rules: list | None = None) -> tuple[dict, Outcome]:
    """rules: (row, RuleDoc) pairs to use instead of the saved ones (rule preview)."""
    from api.rules.apply import active_rules, combine, scoped
    if rules is None:
        rules = await active_rules(db, check.check_type)
    clause, rule_thresholds, applied, problem = combine(rules)
    from api.core import sla
    await sla.load(db)   # the install's SLAs are the SLA check's defaults
    # Curated rules set this org's defaults; a caller's explicit parameter still wins
    thresholds = check.parse({**rule_thresholds, **params})
    fresh, stamps, why = await freshness(db, check.sources, check.max_age_hours)
    if problem:
        outcome = Outcome("error", problem)
    elif not fresh:
        outcome = Outcome("error", why)
    else:
        try:
            with scoped(clause):
                outcome = await check.run(db, thresholds, detail)
        except Exception:
            import logging
            logging.getLogger("open-ctem.grc").exception("check %s failed", check.check_type)
            outcome = Outcome("error", "the check failed to run; see the CTEM log")
    body = {
        "check_type": check.check_type, "check_version": check.version, "name": check.name,
        "result": outcome.result, "summary": outcome.summary[:500], "measured_at": now().isoformat(),
        "thresholds": thresholds, "data_freshness": stamps, "details": outcome.details, "curated_rules": applied,
        "evidence_data": {**outcome.details, "thresholds": thresholds, "check_version": check.version,
                          "curated_rules": applied},
    }
    return body, outcome


def _load() -> None:
    # Import for registration side effects; the modules register into REGISTRY
    from api.grc.checks import endpoint, hygiene, identity, ops, vulns  # noqa: F401


_load()
