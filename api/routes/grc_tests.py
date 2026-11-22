"""GRC > Controls: test a control and attest to it (what was tested, by whom, expected, outcome, pass or fail and
why it failed), each control's testing cadence, and sending the attestation to FairTPRM.

Reading needs grc:read; recording a test needs grc:write; the testing rules are admin only. The person signed in is
the tester: nobody records a test in someone else's name."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin, require_permission
from api.core import control_cadence as cad
from api.core.db import get_session
from api.models.grc import GrcControl, GrcControlTest
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])
Long = Field(min_length=1, max_length=5000)


def _clean_text(v):
    if v is None:
        return v
    v = str(v).strip()
    if any(ord(c) < 32 and c not in "\n\t" for c in v):
        raise ValueError("no control characters")
    return v


class TestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    what_tested: str = Long
    expected_result: str = Long
    outcome: str = Long
    result: Literal["pass", "fail"]
    failure_reason: str | None = Field(None, max_length=5000)
    tested_at: datetime | None = None   # when the test was done; default now

    _t = field_validator("what_tested", "expected_result", "outcome", "failure_reason")(_clean_text)

    @model_validator(mode="after")
    def _rules(self):
        if self.result == "fail" and not (self.failure_reason or "").strip():
            raise ValueError("a failed test needs a failure reason")
        if self.result == "pass":
            self.failure_reason = None
        if self.tested_at is not None:
            at = self.tested_at if self.tested_at.tzinfo else self.tested_at.replace(tzinfo=timezone.utc)
            n = datetime.now(timezone.utc)
            if at > n + timedelta(hours=1) or at < n - timedelta(days=366):
                raise ValueError("the test date must be within the last year, not in the future")
            self.tested_at = at
        for f in ("what_tested", "expected_result", "outcome"):
            if not getattr(self, f):
                raise ValueError(f"{f} is required")
        return self


class CadenceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    by_risk: dict[Literal[cad.RISKS], int] = Field(default_factory=dict)
    default_days: int = Field(365, ge=cad.LIMITS[0], le=cad.LIMITS[1])
    use_control_frequency: bool = True
    controls: dict[str, int] = Field(default_factory=dict, max_length=2000)

    @field_validator("by_risk", "controls")
    @classmethod
    def _bounds(cls, v):
        for k, d in v.items():
            if not cad.LIMITS[0] <= d <= cad.LIMITS[1]:
                raise ValueError(f"{k}: days must be between {cad.LIMITS[0]} and {cad.LIMITS[1]}")
        return v


def acting(u: User) -> str:
    from api.routes.grc_risk_edit import acting_user
    return acting_user(u)


def _row(t: GrcControlTest) -> dict:
    return {"id": str(t.id), "tested_at": t.tested_at.isoformat(), "tested_by": t.tested_by, "what_tested": t.what_tested,
            "expected_result": t.expected_result, "outcome": t.outcome, "result": t.result,
            "failure_reason": t.failure_reason, "next_test_due": t.next_test_due.isoformat() if t.next_test_due else None,
            "fairtprm_status": t.fairtprm_status, "fairtprm_detail": t.fairtprm_detail}


async def _control(db, control_id: uuid.UUID) -> GrcControl:
    c = await db.get(GrcControl, str(control_id))
    if c is None or not c.is_active:
        raise HTTPException(404)
    return c


async def latest_tests(db) -> dict[str, GrcControlTest]:
    """Each control's newest test."""
    newest = (select(GrcControlTest.control_id, func.max(GrcControlTest.tested_at).label("at"))
              .group_by(GrcControlTest.control_id).subquery())
    rows = await db.execute(select(GrcControlTest).join(newest, (GrcControlTest.control_id == newest.c.control_id)
                                                        & (GrcControlTest.tested_at == newest.c.at)))
    return {t.control_id: t for t in rows.scalars()}


async def testing_view(db, c: GrcControl, rules: dict, last: GrcControlTest | None) -> dict:
    when = last.tested_at if last else c.last_tested_at
    return {**cad.due(rules, c, when), "last_result": last.result if last else None,
            "last_tested_by": last.tested_by if last else None}


@router.get("/controls/{control_id}/tests")
async def control_tests(control_id: uuid.UUID, u: User = Depends(require_permission("grc", "read")),
                        db: AsyncSession = Depends(get_session)):
    from api.auth.rbac import _load_user_permissions
    c = await _control(db, control_id)
    tests = (await db.execute(select(GrcControlTest).where(GrcControlTest.control_id == str(c.id))
                              .order_by(GrcControlTest.tested_at.desc()).limit(200))).scalars().all()
    rules = await cad.load(db)
    perms = await _load_user_permissions(u, db)
    return {"control": {"id": str(c.id), "control_ref": c.control_ref, "title": c.title, "risk_level": c.risk_level,
                        "frequency": c.frequency, "effectiveness": c.effectiveness, "control_type": c.control_type,
                        "frameworks": c.frameworks or [], "from_fairtprm": c.source == "fairtprm"},
            "testing": await testing_view(db, c, rules, tests[0] if tests else None),
            "tests": [_row(t) for t in tests],
            "can_test": "admin" in u.role_names or any(p.startswith("grc:write:") for p in perms),
            "can_edit_rules": "admin" in u.role_names, "you": acting(u)}


@router.post("/controls/{control_id}/tests")
async def record_test(control_id: uuid.UUID, body: TestBody, u: User = Depends(require_permission("grc", "write")),
                      db: AsyncSession = Depends(get_session)):
    from api.integrations.fairtprm_tests import send
    c = await _control(db, control_id)
    rules = await cad.load(db)
    at = body.tested_at or datetime.now(timezone.utc)
    days, _ = cad.interval(rules, c)
    newest_before = (await db.execute(select(func.max(GrcControlTest.tested_at))
                                      .where(GrcControlTest.control_id == str(c.id)))).scalar_one()
    t = GrcControlTest(control_id=str(c.id), control_ref=c.control_ref, tested_at=at, tested_by_id=str(u.id),
                       tested_by=acting(u), what_tested=body.what_tested, expected_result=body.expected_result,
                       outcome=body.outcome, result=body.result, failure_reason=body.failure_reason,
                       next_test_due=(at + timedelta(days=days)).date(), frequency_days=days)
    db.add(t)
    await db.flush()
    nb = newest_before if newest_before is None or newest_before.tzinfo else newest_before.replace(tzinfo=timezone.utc)
    if nb is None or at >= nb:   # the newest test sets the control's tested date and effectiveness
        c.last_tested_at = at
        c.effectiveness = "effective" if body.result == "pass" else "ineffective"
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="grc.control_test",
                    resource_type="grc_control", resource_id=str(c.id),
                    detail=f"{c.control_ref or c.title[:60]}: {body.result}"))
    status, detail = await send(db, t, c)
    await db.commit()
    return {"ok": True, "test": _row(t), "fairtprm": {"status": status, "detail": detail}}


@router.post("/control-tests/{test_id}/send")
async def resend(test_id: uuid.UUID, u: User = Depends(require_permission("grc", "write")),
                 db: AsyncSession = Depends(get_session)):
    """Send a test to FairTPRM again (it was down, or its token was read-only). FairTPRM keeps one record per test."""
    from api.integrations.fairtprm_tests import send
    t = await db.get(GrcControlTest, str(test_id))
    if t is None:
        raise HTTPException(404)
    c = await _control(db, uuid.UUID(t.control_id))
    status, detail = await send(db, t, c)
    await db.commit()
    return {"ok": status in ("sent", "summary"), "fairtprm": {"status": status, "detail": detail}}


@router.get("/test-cadence")
async def get_cadence(u: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    controls = (await db.execute(select(GrcControl).where(GrcControl.is_active == True)  # noqa: E712
                                 .order_by(GrcControl.control_ref))).scalars().all()
    return {"rules": await cad.load(db), "defaults": cad.DEFAULTS, "limits": list(cad.LIMITS), "can_edit": "admin" in u.role_names,
            "controls": [{"id": str(c.id), "control_ref": c.control_ref, "title": c.title[:120], "risk_level": c.risk_level,
                          "frequency": c.frequency} for c in controls]}


@router.put("/test-cadence")
async def set_cadence(body: CadenceBody, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    ids = {str(i) for (i,) in (await db.execute(select(GrcControl.id))).all()}
    unknown = [k for k in body.controls if k not in ids]
    if unknown:
        return {"ok": False, "error": "Some of those controls no longer exist; reload and try again."}
    good = await cad.save(db, body.model_dump())
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="grc.test_cadence",
                    resource_type="setting", resource_id=cad.KEY,
                    detail=f"by risk {good['by_risk']}, default {good['default_days']}, {len(good['controls'])} control overrides"))
    await db.commit()
    return {"ok": True, "rules": good}


class ScheduleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default_hours: int
    checks: dict[str, int] = Field(default_factory=dict, max_length=200)

    @model_validator(mode="after")
    def _choices(self):
        from api.core.check_schedule import CHOICES
        for k, v in [("every check", self.default_hours), *self.checks.items()]:
            if v not in CHOICES:
                raise ValueError(f"{k}: choose one of {', '.join(map(str, CHOICES))} hours")
        return self


@router.get("/check-schedule")
async def get_schedule(u: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    """How often the CTEM control checks run, with each check's interval and when it last ran."""
    from api.core import check_schedule as cs
    from api.routes.grc_data import latest_results
    from api.rules.custom import all_checks
    rules, latest = await cs.load(db), await latest_results(db)
    checks = await all_checks(db)
    return {"rules": rules, "choices": list(cs.CHOICES), "can_edit": "admin" in u.role_names,
            "checks": [{"check_type": t, "name": c.name, "hours": cs.hours_for(rules, t),
                        "last_run": latest[t].measured_at.isoformat() if t in latest else None}
                       for t, c in sorted(checks.items(), key=lambda kv: kv[1].name)]}


@router.put("/check-schedule")
async def set_schedule(body: ScheduleBody, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.core import check_schedule as cs
    from api.rules.custom import all_checks
    known = set(await all_checks(db))
    if any(k not in known for k in body.checks):
        return {"ok": False, "error": "Some of those checks no longer exist; reload and try again."}
    good = await cs.save(db, {"default_hours": body.default_hours,
                              "checks": {k: v for k, v in body.checks.items() if v != body.default_hours}})
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="grc.check_schedule",
                    resource_type="setting", resource_id=cs.KEY,
                    detail=f"every {good['default_hours']} h; {len(good['checks'])} checks with their own interval"))
    await db.commit()
    return {"ok": True, "rules": good}
