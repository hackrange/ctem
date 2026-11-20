"""Admin > Curated Rules: JSON rules (open-ctem/curated-rule@1) that scope control checks. Admin only, audited."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.rules import CuratedRule
from api.models.settings import AuditLog
from api.models.user import User
from api.rules.custom import CheckDoc, parse_document
from api.rules.doc import RuleDoc, json_schema

router = APIRouter(prefix="/api/v1/rules", tags=["curated-rules"])


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(..., min_length=5, max_length=2000)


class Preview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict
    rule_id: uuid.UUID | None = None   # editing this rule: preview replaces it instead of adding


def _errors(exc: ValidationError) -> list[str]:
    """Field path + message, without echoing input back."""
    out = []
    for e in exc.errors(include_input=False, include_url=False)[:20]:
        where = ".".join(str(p) for p in e.get("loc", ()) if p != "__root__")
        msg = str(e.get("msg", "invalid")).removeprefix("Value error, ")
        out.append(f"{where}: {msg}" if where else msg)
    return out


def _validate(document: dict) -> RuleDoc | CheckDoc:
    try:
        return parse_document(document)
    except ValidationError as exc:
        raise HTTPException(422, detail={"errors": _errors(exc)}) from None


def _out(r: CuratedRule) -> dict:
    return {"id": str(r.id), "name": r.name, "check": r.check_type, "enabled": r.enabled, "version": r.version,
            "document": r.document, "created_by": r.created_by, "updated_by": r.updated_by,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None}


def _audit(db: AsyncSession, actor: User, action: str, rule: CuratedRule, detail: str) -> None:
    db.add(AuditLog(actor_user_id=str(actor.id), actor_username=actor.username, action=action,
                    resource_type="curated_rule", resource_id=str(rule.id), detail=detail[:500]))


def _check_type(doc: RuleDoc | CheckDoc) -> str:
    return doc.check_type if isinstance(doc, CheckDoc) else doc.check


async def _conflict(db: AsyncSession, doc: RuleDoc | CheckDoc, skip: str | None) -> str | None:
    """Two enabled rules may not set the same threshold to different values; custom check ids are unique."""
    from api.rules.apply import active_rules
    if isinstance(doc, CheckDoc):
        taken = (await db.execute(select(CuratedRule.id, CuratedRule.name).where(
            CuratedRule.check_type == doc.check_type))).all()
        other = next((n for i, n in taken if str(i) != skip), None)
        return f"'{other}' already defines {doc.check_type}" if other else None
    for row, other in await active_rules(db, doc.check):
        if other is None or str(row.id) == skip:
            continue
        for k, v in doc.thresholds.items():
            if k in other.thresholds and other.thresholds[k] != v:
                return f"'{row.name}' already sets {k} to {other.thresholds[k]}"
    return None


async def _remeasure(db: AsyncSession, *check_types: str) -> dict | None:
    """Re-run the checks a rule change touches, so the GRC page and FairTPRM see it now, not at the next daily run."""
    import logging

    from api.grc.evidence import refresh
    out = None
    for ct in dict.fromkeys(check_types):
        try:
            body = await refresh(db, ct)
            out = out or ({k: body[k] for k in ("result", "summary")} if body else None)
        except Exception:
            logging.getLogger("open-ctem.rules").exception("re-measuring %s after a rule change failed", ct)
            await db.rollback()
    return out


async def _get(db: AsyncSession, rule_id: uuid.UUID) -> CuratedRule:
    row = (await db.execute(select(CuratedRule).where(CuratedRule.id == str(rule_id)))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Rule not found")
    return row


@router.get("/schema")
async def schema(_: User = Depends(require_admin)):
    return json_schema()


@router.get("")
async def list_rules(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(CuratedRule).order_by(CuratedRule.check_type, CuratedRule.created_at))).scalars().all()
    return {"rules": [_out(r) for r in rows]}


@router.post("", status_code=201)
async def create_rule(document: dict = Body(..., embed=True), user: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_session)):
    doc = _validate(document)
    clash = await _conflict(db, doc, None)
    if clash:
        raise HTTPException(409, detail={"errors": [clash]})
    ct = _check_type(doc)
    row = CuratedRule(name=doc.name, check_type=ct, document=doc.dump(), enabled=True, version=1,
                      created_by=user.username, updated_by=user.username)
    db.add(row)
    await db.flush()
    _audit(db, user, "rule.create", row, f"{doc.name} on {ct}")
    await db.commit()
    return {**_out(row), "measured": await _remeasure(db, ct)}


@router.put("/{rule_id}")
async def update_rule(rule_id: uuid.UUID, document: dict = Body(..., embed=True), user: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_session)):
    row = await _get(db, rule_id)
    old_check = row.check_type
    doc = _validate(document)
    clash = await _conflict(db, doc, str(row.id))
    if clash:
        raise HTTPException(409, detail={"errors": [clash]})
    row.name, row.check_type, row.document = doc.name, _check_type(doc), doc.dump()
    row.version += 1
    row.updated_by = user.username
    _audit(db, user, "rule.update", row, f"{doc.name} v{row.version}")
    await db.commit()
    return {**_out(row), "measured": await _remeasure(db, row.check_type, old_check)}


@router.put("/{rule_id}/enabled")
async def set_enabled(rule_id: uuid.UUID, enabled: bool = Body(..., embed=True), user: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_session)):
    row = await _get(db, rule_id)
    if enabled and not row.enabled:
        clash = await _conflict(db, _validate(row.document), str(row.id))
        if clash:
            raise HTTPException(409, detail={"errors": [clash]})
    row.enabled = enabled
    row.updated_by = user.username
    _audit(db, user, "rule.enable" if enabled else "rule.disable", row, row.name)
    await db.commit()
    return {**_out(row), "measured": await _remeasure(db, row.check_type)}


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: uuid.UUID, user: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    row = await _get(db, rule_id)
    check_type = row.check_type
    _audit(db, user, "rule.delete", row, f"{row.name} ({row.check_type}) v{row.version}")
    await db.delete(row)
    await db.commit()
    await _remeasure(db, check_type)


@router.post("/preview")
async def preview(body: Preview, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    """The check's result with the saved rules, then with this one, plus which devices it drops."""
    from sqlalchemy import func, not_

    from api.grc.checks import REGISTRY, evaluate
    from api.models.device import Device
    from api.rules.apply import active_rules, combine, rule_clause

    try:
        doc = parse_document(body.document)
    except ValidationError as exc:
        return {"errors": _errors(exc)}   # 200, because the load balancer replaces 4xx bodies
    if isinstance(doc, CheckDoc):
        return await _preview_check(db, doc, body.rule_id)
    check = REGISTRY[doc.check]
    saved = await active_rules(db, doc.check)
    others = [(r, d) for r, d in saved if body.rule_id is None or str(r.id) != str(body.rule_id)]
    draft_row = CuratedRule(id=str(body.rule_id or uuid.uuid4()), name=doc.name, check_type=doc.check, document=doc.dump(), version=0)
    before, _o = await evaluate(db, check, {}, rules=saved)
    after, _o = await evaluate(db, check, {}, rules=[*others, (draft_row, doc)])
    out = {"before": {k: before[k] for k in ("result", "summary", "thresholds")},
           "after": {k: after[k] for k in ("result", "summary", "thresholds")}}
    clause = rule_clause(doc)
    if clause is not None:
        total = (await db.execute(select(func.count()).select_from(Device))).scalar_one()
        kept = (await db.execute(select(func.count()).select_from(Device).where(clause))).scalar_one()
        dropped = (await db.execute(select(Device.hostname, Device.device_type, Device.os).where(not_(clause))
                                    .order_by(Device.hostname).limit(25))).all()
        out["devices"] = {"total": total, "in_scope": kept, "out_of_scope": total - kept,
                          "out_of_scope_sample": [{"hostname": h, "device_type": t.value if t else None, "os": o}
                                                  for h, t, o in dropped]}
    _c, _t, _a, problem = combine([*others, (draft_row, doc)])
    out["problem"] = problem
    return out


async def _preview_check(db: AsyncSession, doc: CheckDoc, rule_id) -> dict:
    """What the new check would report right now, and the first devices it would list."""
    from api.grc.checks import evaluate
    from api.rules.custom import build
    clash = await _conflict(db, doc, str(rule_id) if rule_id else None)
    draft_row = CuratedRule(id=str(rule_id or uuid.uuid4()), name=doc.name, check_type=doc.check_type,
                            document=doc.dump(), version=0)
    after, outcome = await evaluate(db, build(draft_row, doc), {}, detail=True, rules=[])
    return {"kind": "check", "check_type": doc.check_type, "problem": clash,
            "after": {k: after[k] for k in ("result", "summary", "thresholds", "details")},
            "listed": len(outcome.rows), "sample": [{c: r.get(c) for c in outcome.columns} for r in outcome.rows[:25]]}


@router.post("/validate")
async def validate(body: Preview, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    """{"valid", "errors"} in a 200 so the editor can show every problem; saving re-checks all of it."""
    try:
        doc = parse_document(body.document)
    except ValidationError as exc:
        return {"valid": False, "errors": _errors(exc)}
    clash = await _conflict(db, doc, str(body.rule_id) if body.rule_id else None)
    return {"valid": clash is None, "errors": [clash] if clash else [], "document": doc.dump()}


@router.post("/draft")
async def ai_draft(body: Draft, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    """With AI configured, plain English becomes a draft rule; the draft is validated before it's shown."""
    from api.rules.ai_draft import draft
    out = await draft(db, body.text)
    if out.get("document") is not None:
        try:
            out["document"] = parse_document(out["document"]).dump()
            out["errors"] = []
        except ValidationError as exc:
            out["errors"] = _errors(exc)   # still shown, so the admin can fix it
    return out
