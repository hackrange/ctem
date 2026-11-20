"""Turn curated rules into a device filter for one check run. Allow-listed columns only; no rule text reaches SQL."""
from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, false, func, not_, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.rules import CuratedRule  # registers the table wherever checks are loaded
from api.rules.doc import CUSTOM_SCHEMA_ID, Filters, RuleDoc

_SCOPE: ContextVar = ContextVar("curated_device_scope", default=None)


def device_scope():
    """The active rules' device condition for the check being run, or everything."""
    clause = _SCOPE.get()
    return true() if clause is None else clause


def _like(text: str) -> str:
    return text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _glob(pattern: str) -> str:
    return _like(pattern).replace("*", "%").replace("?", "_")


def _seen_columns():
    from api.models.device import Device
    return (Device.last_seen, Device.edr_last_seen, Device.ad_last_logon)


def filters_clause(f: Filters, any_of: bool = False):
    """Listed conditions all hold (AND), or any one does with any_of; values in one list are alternatives (OR).
    NULLs compare as empty text."""
    from api.models.device import Device, DeviceTag, DeviceType
    from api.models.tag import Tag

    seen_cols = _seen_columns()
    parts = []
    if f.device_types:
        parts.append(Device.device_type.in_([DeviceType(t) for t in f.device_types]))
    if f.os_contains:
        os_ = func.lower(func.coalesce(Device.os, ""))
        parts.append(or_(*(os_.like(f"%{_like(x)}%", escape="\\") for x in f.os_contains)))
    if f.hostname_patterns:
        host = func.lower(func.coalesce(Device.hostname, ""))
        parts.append(or_(*(host.like(_glob(p), escape="\\") for p in f.hostname_patterns)))
    if f.tags:
        tagged = select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(Tag.name.in_(f.tags))
        parts.append(Device.id.in_(tagged))
    if f.sources:  # validated against SOURCE_CODES, so safe inside LIKE
        srcs = func.coalesce(Device.sources, "")
        parts.append(or_(*(srcs.like(f"%,{s},%") for s in f.sources)))
    if f.criticality:
        parts.append(func.coalesce(Device.criticality, "").in_(f.criticality))
    if f.internet_facing is not None:
        parts.append(Device.is_internet_exposed == f.internet_facing)
    if f.sources_only:  # validated codes; strip each listed one, nothing else may remain
        rest = func.coalesce(Device.sources, "")
        for code in f.sources_only:
            rest = func.replace(rest, f",{code},", ",")
        parts.append(and_(func.coalesce(Device.sources, "").notin_(["", ","]), rest == ","))
    if f.ad_joined is not None:
        parts.append(Device.ad_joined.is_(True) if f.ad_joined
                     else or_(Device.ad_joined.is_(False), Device.ad_joined.is_(None)))
    if f.not_seen_days:  # none of the signs of life is recent (NULL counts as never)
        cut = datetime.now(timezone.utc) - timedelta(days=f.not_seen_days)
        parts.append(and_(*(or_(c.is_(None), c < cut) for c in seen_cols)))
    if f.seen_within_days:
        cut = datetime.now(timezone.utc) - timedelta(days=f.seen_within_days)
        parts.append(or_(*(c >= cut for c in seen_cols)))
    if f.inventory_status:
        from api.models.device import DeviceAssignment
        flagged = [s for s in f.inventory_status if s != "in_use"]
        alts = []
        if flagged:
            alts.append(Device.id.in_(select(DeviceAssignment.device_id).where(DeviceAssignment.status.in_(flagged))))
        if "in_use" in f.inventory_status:
            alts.append(not_(Device.id.in_(select(DeviceAssignment.device_id).where(DeviceAssignment.status.is_not(None)))))
        parts.append(or_(*alts))
    if f.ad_stale_days:  # never logged on counts as stale
        cut = datetime.now(timezone.utc) - timedelta(days=f.ad_stale_days)
        parts.append(or_(Device.ad_last_logon.is_(None), Device.ad_last_logon < cut))
    if f.edr_contained is not None:  # unknown counts as not contained
        parts.append(Device.edr_contained.is_(True) if f.edr_contained
                     else or_(Device.edr_contained.is_(False), Device.edr_contained.is_(None)))
    if not parts:
        return None
    return or_(*parts) if any_of else and_(*parts)


def rule_clause(doc: RuleDoc):
    inc = filters_clause(doc.scope.include) if doc.scope.include else None
    # include: every condition holds; exclude: a device matching any one condition is left out
    # a list of exclude blocks: a device meeting every condition of any one block is left out
    ex = doc.scope.exclude
    if isinstance(ex, list):
        blocks = [c for c in (filters_clause(b) for b in ex) if c is not None]
        exc = or_(*blocks) if blocks else None
    else:
        exc = filters_clause(ex, any_of=True) if ex else None
    parts = ([inc] if inc is not None else []) + ([not_(exc)] if exc is not None else [])
    return and_(*parts) if parts else None


async def active_rules(db: AsyncSession, check_type: str) -> list[tuple[object, RuleDoc]]:
    rows = (await db.execute(select(CuratedRule).where(CuratedRule.check_type == check_type, CuratedRule.enabled == True)  # noqa: E712
                             .order_by(CuratedRule.created_at))).scalars().all()
    out = []
    for r in rows:
        if isinstance(r.document, dict) and r.document.get("schema") == CUSTOM_SCHEMA_ID:
            continue  # the definition of a custom check, not a rule that scopes one
        try:
            out.append((r, RuleDoc.model_validate(r.document)))
        except ValueError:
            out.append((r, None))  # a rule that no longer validates (check changed) blocks the check below
    return out


def combine(rules: list[tuple[object, RuleDoc | None]]) -> tuple[object | None, dict, list[dict], str | None]:
    """(device clause, threshold defaults, rules applied, problem)."""
    clauses, thresholds, applied = [], {}, []
    for row, doc in rules:
        if doc is None:
            return false(), {}, [], f"curated rule '{row.name}' no longer fits this check; fix or disable it"
        c = rule_clause(doc)
        if c is not None:
            clauses.append(c)
        thresholds.update(doc.thresholds)
        applied.append({"id": str(row.id), "name": row.name, "version": row.version})
    return (and_(*clauses) if clauses else None), thresholds, applied, None


class scoped:
    """with scoped(clause): run the check with that device filter."""

    def __init__(self, clause):
        self.clause = clause

    def __enter__(self):
        self.token = _SCOPE.set(self.clause)

    def __exit__(self, *exc):
        _SCOPE.reset(self.token)
