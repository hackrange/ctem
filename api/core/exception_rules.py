"""Rule exceptions (open-ctem/exception-rule@1): an exception defined by which devices and which
vulnerabilities it covers, rather than a list. It stays dynamic: every rescore covers new findings that match
and releases findings on devices that stop matching.

Devices use the same allow-listed filters as curated rules (hostname pattern, OS starts with, device type,
tags, sources...). Vulnerabilities are optional: no filter means every vulnerability on those devices.
Nothing in a rule is ever run as code or SQL."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator
from sqlalchemy import and_, func, or_, select

from api.rules.doc import Filters, Scope

SCHEMA_ID = "open-ctem/exception-rule@1"
MAX_DEVICES = 100_000   # a rule matching more than this is too broad to be an exception
WARN_DEVICES = 50       # above this, the preview and the dialog say plainly how many hosts it excludes
Cve = Annotated[str, StringConstraints(strip_whitespace=True, to_upper=True, pattern=r"^[Cc][Vv][Ee]-\d{4}-\d{4,7}$")]
Words = Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=64, pattern=r"^[^\x00-\x1f<>]+$")]


class VulnFilter(BaseModel):
    """Every listed condition must hold; values inside one list are alternatives. Empty: every vulnerability."""
    model_config = ConfigDict(extra="forbid")
    cve_ids: list[Cve] | None = Field(None, max_length=200)
    title_contains: list[Words] | None = Field(None, max_length=20, description="case-insensitive text in the title")
    min_cvss: float | None = Field(None, ge=0, le=10)
    max_cvss: float | None = Field(None, ge=0, le=10)
    kev: bool | None = Field(None, description="true: only CISA KEV; false: leave KEV out")
    sources: list[str] | None = Field(None, max_length=10, description="the finding came from one of these sources")

    @field_validator("sources", mode="before")
    @classmethod
    def _known(cls, v):
        if v is None:
            return v
        from api.core.device_match import SOURCE_CODES
        from api.rules.doc import _SOURCE_ALIASES
        if not isinstance(v, list):
            raise ValueError("sources must be a list")
        v = [_SOURCE_ALIASES.get(k, k) for k in (str(x).strip().lower().replace(" ", "_").replace("-", "_")[:64] for x in v)]
        bad = [x for x in v if x not in SOURCE_CODES]
        if bad:
            raise ValueError(f"unknown source {bad[0]!r}; use one of {sorted(SOURCE_CODES)}")
        return v

    def empty(self) -> bool:
        return all(getattr(self, f) is None for f in type(self).model_fields)


class ExceptionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_: Literal[SCHEMA_ID] = Field(SCHEMA_ID, alias="schema")
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=120, pattern=r"^[^\x00-\x1f<>]+$")]
    devices: Scope = Field(description="which devices; include must name at least one condition")
    vulnerabilities: VulnFilter = Field(default_factory=VulnFilter)

    @model_validator(mode="after")
    def _narrow(self):
        if not self.devices.include or self.devices.include.empty():
            raise ValueError("say which devices it covers (devices.include needs at least one condition)")
        v = self.vulnerabilities
        if v.min_cvss is not None and v.max_cvss is not None and v.min_cvss > v.max_cvss:
            raise ValueError("min_cvss is above max_cvss")
        return self

    def dump(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=True, mode="json")


def parse(doc) -> ExceptionRule:
    """Validate a rule document (raises pydantic.ValidationError or ValueError)."""
    if not isinstance(doc, dict):
        raise ValueError("a rule is a JSON object")
    return ExceptionRule.model_validate(doc)


def device_clause(rule: ExceptionRule):
    """SQL condition on Device, the same way curated rules read a scope: include all, exclude any."""
    from sqlalchemy import not_

    from api.rules.apply import filters_clause
    inc = filters_clause(rule.devices.include)
    ex = rule.devices.exclude
    if isinstance(ex, list):
        blocks = [c for c in (filters_clause(b) for b in ex) if c is not None]
        exc = or_(*blocks) if blocks else None
    else:
        exc = filters_clause(ex, any_of=True) if ex else None
    return and_(inc, not_(exc)) if exc is not None else inc


def vuln_clause(rule: ExceptionRule):
    """SQL condition on Vulnerability, or None for every vulnerability."""
    from api.models.vuln import Vulnerability
    from api.rules.apply import _like
    v, parts = rule.vulnerabilities, []
    if v.cve_ids:
        parts.append(func.upper(func.coalesce(Vulnerability.cve_id, "")).in_(v.cve_ids))
    if v.title_contains:
        title = func.lower(func.coalesce(Vulnerability.title, ""))
        parts.append(or_(*(title.like(f"%{_like(w)}%", escape="\\") for w in v.title_contains)))
    if v.min_cvss is not None:
        parts.append(func.coalesce(Vulnerability.cvss_base, 0) >= v.min_cvss)
    if v.max_cvss is not None:
        parts.append(func.coalesce(Vulnerability.cvss_base, 0) <= v.max_cvss)
    if v.kev is not None:
        parts.append(Vulnerability.is_kev.is_(v.kev))
    return and_(*parts) if parts else None


def covers(rule: ExceptionRule):
    """SQL condition on Finding: the findings this rule covers (any status)."""
    from api.models.device import Device
    from api.models.vuln import Finding, Vulnerability
    cond = [Finding.device_id.in_(select(Device.id).where(device_clause(rule)))]
    vc = vuln_clause(rule)
    if vc is not None:
        cond.append(Finding.vuln_id.in_(select(Vulnerability.id).where(vc)))
    if rule.vulnerabilities.sources:
        cond.append(Finding.source.in_(rule.vulnerabilities.sources))
    return and_(*cond)


async def preview(db, rule: ExceptionRule) -> dict:
    """What the rule covers right now: devices (with a sample), open findings, KEV among them."""
    from api.models.device import Device
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    from api.routes import device_query as dq
    dc = device_clause(rule)
    devices = (await db.execute(select(func.count()).select_from(Device).where(dc))).scalar_one()
    sample = [dq.short_name(h) for h in (await db.execute(
        select(Device.hostname).where(dc).order_by(Device.hostname).limit(15))).scalars()]
    open_ = Finding.status.in_([FindingStatus.open, FindingStatus.in_progress])
    findings, kev, vulns = (await db.execute(
        select(func.count(), func.count().filter(Vulnerability.is_kev.is_(True)), func.count(func.distinct(Finding.vuln_id)))
        .select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(covers(rule), open_))).one()
    return {"devices": devices, "sample": sample, "open_findings": findings, "kev_findings": kev,
            "vulnerabilities": vulns, "too_broad": devices > MAX_DEVICES, "max_devices": MAX_DEVICES,
            "warning": (f"This exception will exclude {devices:,} hosts ({findings:,} open findings, {kev:,} of them KEV) "
                        "from risk, SLA and the vulnerability checks until it ends.") if devices > WARN_DEVICES or kev else None}


def describe(rule: ExceptionRule) -> str:
    """One line for lists: 'Rule: Legacy Cisco gear (hostname CAN*, OS starts with Cisco IOS; all vulnerabilities)'."""
    def part(f: Filters | None) -> str:
        if not f:
            return ""
        bits = []
        for k, v in f.model_dump(exclude_none=True).items():
            label = k.replace("_", " ")
            bits.append(f"{label} {', '.join(map(str, v)) if isinstance(v, list) else v}")
        return "; ".join(bits)
    inc = part(rule.devices.include)
    vul = part(rule.vulnerabilities) or "all vulnerabilities"   # same dump shape works for VulnFilter
    return f"Rule: {rule.name} ({inc}; {vul})"[:300]
