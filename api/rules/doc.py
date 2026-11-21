"""The curated-rule JSON standard (open-ctem/curated-rule@1) and its validation.

A rule narrows which devices a control check counts, and can move its thresholds inside the bounds the
check already allows. Filters are a fixed allow-list; nothing in a rule is ever run as code or SQL.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

SCHEMA_ID = "open-ctem/curated-rule@1"
CUSTOM_SCHEMA_ID = "open-ctem/custom-check@1"   # a rule that defines a new check (api/rules/custom.py)
DEVICE_TYPES = ("workstation", "server", "network_device", "cloud_instance", "unknown")
INVENTORY = ("in_use", "shipped", "lost", "stolen", "returned")
CRITICALITY = ("Very High", "High", "Medium", "Low", "Very Low")

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64, pattern=r"^[^\x00-\x1f<>]+$")]
Glob = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.*?_-]+$")]
TagName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128, pattern=r"^[^\x00-\x1f<>]+$")]


_SOURCE_ALIASES = {"crowdstrike_falcon": "crowdstrike", "falcon": "crowdstrike", "cs": "crowdstrike",
                   "insightvm": "rapid7_insightvm", "r7": "rapid7_insightvm", "defender": "msdefender",
                   "microsoft_defender": "msdefender", "ms_defender": "msdefender", "s1": "sentinelone",
                   "active_directory": "ldap", "ad": "ldap"}


class Filters(BaseModel):
    """Every listed condition must hold (AND); values inside one list are alternatives (OR)."""
    model_config = ConfigDict(extra="forbid")

    device_types: list[Literal[DEVICE_TYPES]] | None = Field(None, max_length=5)
    os_contains: list[Text] | None = Field(None, max_length=20, description="case-insensitive text in the OS name")
    os_starts_with: list[Text] | None = Field(None, max_length=20,
                                              description="case-insensitive start of the OS name, e.g. 'VMware ESXi'")
    hostname_patterns: list[Glob] | None = Field(None, max_length=50, description="* and ? wildcards, case-insensitive")
    tags: list[TagName] | None = Field(None, max_length=50, description="device has any of these tags")
    sources: list[str] | None = Field(None, max_length=20, description="reported by any of these sources")
    criticality: list[Literal[CRITICALITY]] | None = Field(None, max_length=5)
    internet_facing: bool | None = None
    edr_contained: bool | None = Field(None, description="true: the EDR has network-contained (isolated) the device")

    ad_joined: bool | None = Field(None, description="true: the device is an AD computer object")
    ad_stale_days: int | None = Field(None, ge=1, le=3650, description="no AD logon for at least this many days, or never")
    sources_only: list[str] | None = Field(None, max_length=20, description="reported by these sources and by no other")
    not_seen_days: int | None = Field(None, ge=1, le=3650,
                                      description="no sign of life (scan, EDR heartbeat or AD logon) for this many days, or ever")
    seen_within_days: int | None = Field(None, ge=1, le=3650,
                                         description="a scan, EDR heartbeat or AD logon within this many days (online recently)")
    inventory_status: list[Literal[INVENTORY]] | None = Field(
        None, max_length=5, description="inventory status; in_use means no shipped/lost/stolen/returned status")

    @field_validator("sources", "sources_only", mode="before")
    @classmethod
    def _known_sources(cls, v):
        if v is None:
            return v
        from api.core.device_match import SOURCE_CODES
        if not isinstance(v, list):
            raise ValueError("sources must be a list")
        # "CrowdStrike", "Rapid7 InsightVM" and "rapid7-insightvm" all mean the stored code
        v = [_SOURCE_ALIASES.get(k, k) for k in
             (str(s).strip().lower().replace(" ", "_").replace("-", "_")[:64] for s in v)]
        bad = [s for s in v if s not in SOURCE_CODES]
        if bad:
            raise ValueError(f"unknown source {bad[0]!r}; use one of {sorted(SOURCE_CODES)}")
        return v

    def empty(self) -> bool:
        return all(getattr(self, f) is None for f in type(self).model_fields)


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    include: Filters | None = Field(None, description="count only devices that meet every condition")
    exclude: Filters | list[Filters] | None = Field(
        None, description="one block: leave out devices that meet any one condition. A list of blocks: leave out "
                          "devices that meet every condition of any one block (for combinations such as "
                          "'only rapid7_insightvm AND not seen for 5 days')")

    @field_validator("exclude")
    @classmethod
    def _blocks(cls, v):
        if isinstance(v, list):
            if len(v) > 10:
                raise ValueError("at most 10 exclude blocks")
            v = [b for b in v if not b.empty()] or None
        return v

    def blocks(self) -> list[Filters]:
        """Every filter block in this scope, for emptiness and source checks."""
        ex = self.exclude if isinstance(self.exclude, list) else [self.exclude] if self.exclude else []
        return [b for b in ([self.include] if self.include else []) + ex if b is not None]


class RuleDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_: Literal[SCHEMA_ID] = Field(SCHEMA_ID, alias="schema")
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=120, pattern=r"^[^\x00-\x1f<>]+$")]
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]*$")] = ""
    check: Annotated[str, StringConstraints(pattern=r"^ctem_[a-z0-9_]{1,60}$")]
    scope: Scope = Field(default_factory=Scope)
    thresholds: dict[Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,40}$")], int] = Field(default_factory=dict, max_length=10)

    @model_validator(mode="after")
    def _fits_the_check(self):
        from api.grc.checks import REGISTRY
        check = REGISTRY.get(self.check)
        if check is None:
            raise ValueError(f"unknown check {self.check!r}")
        has_scope = any(not f.empty() for f in self.scope.blocks())
        if has_scope and not check.device_scoped:
            raise ValueError(f"{self.check} doesn't count devices, so it can't be scoped by device")
        if not has_scope and not self.thresholds:
            raise ValueError("a rule needs a scope or a threshold change")
        check.parse(self.thresholds)  # same bounds as the check itself; raises ValueError
        return self

    def dump(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=True, mode="json")


def json_schema() -> dict:
    """Published at /api/v1/rules/schema so people (and the AI) write rules to one standard."""
    from api.grc.checks import REGISTRY
    schema = RuleDoc.model_json_schema(by_alias=True)
    schema["$id"] = SCHEMA_ID
    schema["title"] = "open-ctem curated rule"
    schema["x-checks"] = {k: {"name": c.name, "device_scoped": c.device_scoped,
                              "thresholds": {n: {"default": t.default, "min": t.lo, "max": t.hi} for n, t in c.thresholds.items()}}
                          for k, c in sorted(REGISTRY.items())}
    from api.rules.custom import custom_json_schema
    schema["x-custom-check"] = custom_json_schema()
    return schema
