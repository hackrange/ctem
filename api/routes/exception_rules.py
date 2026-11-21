"""Rule exceptions (admin only): an exception for the devices and vulnerabilities a rule describes, drafted from
plain English by the AI when it's set up, always validated and previewed before it's created.

The same rules as every exception: a reason, compensating controls, and an end date at most a year out.
Refusals answer 200 with ok: false because the load balancer replaces 4xx bodies."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core import exception_rules as er
from api.core import vuln_exceptions as vx
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import User
from api.models.vuln import ExceptionScope, ExceptionStatus, VulnException
from api.routes.vuln_exceptions import Text

router = APIRouter(prefix="/api/v1/exceptions/rule", tags=["exceptions"])


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule: dict


class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=5, max_length=1000)


class NewRuleException(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule: dict
    reason: Text = Field(min_length=10)
    compensating_controls: Text = Field(min_length=10)
    expires_on: date

    @model_validator(mode="after")
    def _dates(self):
        today = datetime.now(timezone.utc).date()
        if not today < self.expires_on <= today + timedelta(days=vx.MAX_DAYS):
            raise ValueError(f"expires_on must be in the next {vx.MAX_DAYS} days")
        return self


def _errors(exc: Exception) -> list[str]:
    if isinstance(exc, ValidationError):
        out = []
        for e in exc.errors()[:8]:
            where = ".".join(str(p) for p in e.get("loc", ()) if p != "__root__")
            msg = str(e.get("msg", "")).removeprefix("Value error, ")
            out.append(f"{where}: {msg}" if where else msg)
        return out
    return [str(exc)[:200]]


def _parse(doc: dict):
    try:
        return er.parse(doc), None
    except (ValidationError, ValueError) as exc:
        return None, {"ok": False, "error": "The rule isn't valid: " + "; ".join(_errors(exc))}


@router.post("/preview")
async def preview(body: RuleIn, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    rule, bad = _parse(body.rule)
    if bad:
        return bad
    return {"ok": True, "rule": rule.dump(), "summary": er.describe(rule), **await er.preview(db, rule)}


@router.post("/draft")
async def draft(body: DraftIn, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.core.exception_rules_ai import draft as ai_draft
    out = await ai_draft(db, body.text)
    if out.get("document"):
        rule, bad = _parse(out["document"])
        if bad:
            return {"available": True, "document": out["document"], "error": bad["error"], "note": out.get("note")}
        out["document"] = rule.dump()
    return out


@router.post("")
async def create(body: NewRuleException, u: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    rule, bad = _parse(body.rule)
    if bad:
        return bad
    p = await er.preview(db, rule)
    if p["too_broad"]:
        return {"ok": False, "error": f"That rule matches {p['devices']:,} devices. An exception can cover at most "
                                      f"{er.MAX_DEVICES:,}; narrow it down."}
    if not p["devices"]:
        return {"ok": False, "error": "That rule matches no devices yet. Check the hostname and OS conditions."}
    at = vx.now()
    exc = VulnException(vuln_id=None, scope=ExceptionScope.rule, name=rule.name, rule=rule.dump(),
                        reason=body.reason, compensating_controls=body.compensating_controls,
                        expires_at=vx.end_of_day(body.expires_on), status=ExceptionStatus.approved,
                        requested_by_id=str(u.id), requested_by=u.username, requested_at=at,
                        decided_by=u.username, decided_at=at)
    db.add(exc)
    await db.flush()
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="exception.create",
                    resource_type="vuln_exception", resource_id=str(exc.id),
                    detail=f"{er.describe(rule)} until {body.expires_on.isoformat()}"[:500]))
    touched = await vx.apply(db, exc)
    await db.commit()
    await vx.rescore(db, touched)
    return {"ok": True, "id": str(exc.id), "status": exc.status.value, "findings_covered": exc.findings_covered,
            "devices": p["devices"]}
