"""Custom control checks defined by a curated rule (open-ctem/custom-check@1).

An admin describes a population of devices and a condition; CTEM turns it into a control check named
ctem_custom_<id> that the GRC page, the remediation list and FairTPRM monitors use like a built-in one.
Everything is the same allow-listed filters as curated rules: no code or SQL comes from the document.
"""
from __future__ import annotations

import logging
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from sqlalchemy import and_, func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from api.rules.doc import CUSTOM_SCHEMA_ID, Filters, Text

log = logging.getLogger("open-ctem.rules")
PREFIX = "ctem_custom_"
# measure -> threshold name -> (default, min, max, help)
_LIMITS = {
    "count": {"pass_max": (0, 0, 1_000_000, "pass at or below this many matching devices"),
              "warn_max": (10, 0, 1_000_000, "warning at or below this many matching devices")},
    "percent": {"pass_at": (98, 0, 100, "pass when at least this % of the population matches"),
                "warn_at": (90, 0, 100, "warning when at least this % matches")},
}


class CheckDoc(BaseModel):
    """count: how many devices in the population match (fewer is better), and the list shows them.
    percent: the share of the population that matches (more is better), and the list shows the rest."""
    model_config = ConfigDict(extra="forbid")

    schema_: Literal[CUSTOM_SCHEMA_ID] = Field(..., alias="schema")
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=80, pattern=r"^[^\x00-\x1f<>]+$")]
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000,
                                                  pattern=r"^[^\x00-\x08\x0b-\x1f<>]*$")] = ""
    id: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[a-z][a-z0-9_]{2,40}$")] = Field(
        ..., description="lowercase; the check is called ctem_custom_<id>")
    measure: Literal["count", "percent"]
    population: Filters = Field(default_factory=Filters, description="the devices this check looks at")
    match: Filters = Field(..., description="the condition counted (count) or required (percent)")
    thresholds: dict[Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,40}$")], int] = Field(default_factory=dict,
                                                                                              max_length=4)
    controls: list[Text] = Field(default_factory=list, max_length=10, description="suggested control mappings")

    @model_validator(mode="after")
    def _fits(self):
        if self.match.empty():
            raise ValueError("match needs at least one condition")
        allowed = _LIMITS[self.measure]
        unknown = set(self.thresholds) - set(allowed)
        if unknown:
            raise ValueError(f"a {self.measure} check takes thresholds {sorted(allowed)}, not {sorted(unknown)[0]!r}")
        t = self.limits()
        for k, (_d, lo, hi, _h) in allowed.items():
            if not lo <= t[k] <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
        if self.measure == "count" and t["warn_max"] < t["pass_max"]:
            raise ValueError("warn_max must be at least pass_max")
        if self.measure == "percent" and t["warn_at"] > t["pass_at"]:
            raise ValueError("warn_at must be at most pass_at")
        return self

    @property
    def check_type(self) -> str:
        return PREFIX + self.id

    def limits(self) -> dict[str, int]:
        return {k: self.thresholds.get(k, d[0]) for k, d in _LIMITS[self.measure].items()}

    def dump(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=True, mode="json")


def custom_json_schema() -> dict:
    s = CheckDoc.model_json_schema(by_alias=True)
    s["$id"], s["title"] = CUSTOM_SCHEMA_ID, "open-ctem custom control check"
    s["x-thresholds"] = {m: {k: {"default": d, "min": lo, "max": hi, "help": h} for k, (d, lo, hi, h) in v.items()}
                         for m, v in _LIMITS.items()}
    return s


def parse_document(document: dict):
    """A custom-check definition or a scoping rule, chosen by its schema. Raises pydantic ValidationError."""
    from api.rules.doc import RuleDoc
    if isinstance(document, dict) and document.get("schema") == CUSTOM_SCHEMA_ID:
        return CheckDoc.model_validate(document)
    return RuleDoc.model_validate(document)


def _sources(doc: CheckDoc) -> tuple[str, ...]:
    """Integrations whose freshness the result depends on."""
    from api.grc.checks import DIRECTORY, EDR, SCANNERS
    found: set[str] = set()
    for f in (doc.population, doc.match):
        found |= set(f.sources or []) | set(f.sources_only or [])
        if f.ad_joined is not None or f.ad_stale_days:
            found.add("ldap")
    return tuple(sorted(found)) or tuple(dict.fromkeys(EDR + SCANNERS + DIRECTORY))


def build(row, doc: CheckDoc):
    """A Check object for this definition; row supplies the version."""
    from sqlalchemy import not_

    from api.grc.checks import Check, Outcome, Threshold, grade_high, grade_low, pct
    from api.grc.checks.endpoint import MAX_ROWS, _row
    from api.models.device import Device
    from api.rules.apply import filters_clause

    pop = filters_clause(doc.population)
    hit = filters_clause(doc.match)
    ad = any(f.ad_joined is not None or f.ad_stale_days for f in (doc.population, doc.match))

    async def count(db: AsyncSession, *where) -> int:
        return (await db.execute(select(func.count()).select_from(Device).where(*where))).scalar_one()

    async def run(db: AsyncSession, t: dict, detail: bool):
        base = pop if pop is not None else true()
        total = await count(db, base)
        if not total and doc.measure == "percent":   # a share of nothing can't be measured
            return Outcome("error", "no devices are in this check's population")
        # count: an empty population means nothing to flag (stale source data is caught by freshness)
        n = await count(db, base, hit)
        p = pct(n, total)
        if doc.measure == "count":
            out = Outcome(grade_low(n, t["pass_max"], t["warn_max"]), f"{n:,} of {total:,} devices match ({p}%)" if total else "no devices are in this check's population, so none match",
                          {"population": total, "matching": n, "matching_pct": p})
            listed = and_(base, hit)
        else:
            out = Outcome(grade_high(p, t["pass_at"], t["warn_at"]), f"{p}% of {total:,} devices meet the check ({n:,})",
                          {"population": total, "meeting": n, "meeting_pct": p})
            listed = and_(base, not_(Device.id.in_(select(Device.id).where(hit))))   # the ones to fix
        if detail:
            out.columns = ["hostname", "os", "device_type", "last_seen", "sources"] + (["ad_last_logon"] if ad else [])
            found = await db.execute(select(Device).where(listed).order_by(Device.hostname).limit(MAX_ROWS))
            out.rows = [{**_row(d), **({"ad_last_logon": d.ad_last_logon.isoformat() if d.ad_last_logon else "never"}
                                       if ad else {})} for d in found.scalars()]
        return out

    limits = {k: Threshold(doc.limits()[k], lo, hi, h) for k, (_d, lo, hi, h) in _LIMITS[doc.measure].items()}
    return Check(doc.check_type, doc.name, doc.description or f"Custom check ({doc.measure})", int(row.version or 1),
                 _sources(doc), tuple(doc.controls), limits, run)


def _broken(row):
    from api.grc.checks import Check, Outcome

    async def run(_db, _t, _detail):
        return Outcome("error", f"the custom check '{row.name}' no longer validates; fix it in Admin > Curated Rules")
    return Check(row.check_type, row.name, "Custom check (needs fixing)", int(row.version or 1), (), (), {}, run)


async def custom_checks(db: AsyncSession) -> dict:
    from api.models.rules import CuratedRule
    rows = (await db.execute(select(CuratedRule).where(CuratedRule.check_type.startswith(PREFIX, autoescape=True),
                                                       CuratedRule.enabled == True)  # noqa: E712
                             .order_by(CuratedRule.created_at))).scalars().all()
    out = {}
    for r in rows:
        try:
            doc = CheckDoc.model_validate(r.document)
        except ValueError:
            log.warning("custom check %s no longer validates", r.check_type)
            out[r.check_type] = _broken(r)
            continue
        out[doc.check_type] = build(r, doc)
    return out


async def all_checks(db: AsyncSession) -> dict:
    """Built-in checks plus this organization's custom ones."""
    from api.grc.checks import REGISTRY
    return {**REGISTRY, **await custom_checks(db)}


async def get_check(db: AsyncSession, check_type: str):
    from api.grc.checks import REGISTRY
    if check_type in REGISTRY:
        return REGISTRY[check_type]
    if not check_type.startswith(PREFIX):
        return None
    return (await custom_checks(db)).get(check_type)
