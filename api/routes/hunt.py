"""Threat hunt API. Cyber and admin only; every hunt result belongs to whoever ran it."""
from __future__ import annotations

import json
import logging

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])
log = logging.getLogger("open-ctem.hunt")
_templates = Jinja2Templates(directory="api/web/templates")
from api.web.assets import install as _install_assets
_install_assets(_templates)

_OWNER_TTL = 86400
_TIME = "^(24h|7d|30d|all)$"


class HuntQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    time_range: str = Field("7d", pattern=_TIME)


class HuntSearchRequest(BaseModel):
    spl: str = Field(min_length=1, max_length=2000)
    time_range: str = Field("7d", pattern=_TIME)


def _redis():
    import redis
    from api.core.config import get_settings
    return redis.from_url(get_settings().redis_url, decode_responses=True)


def _remember_owner(task_id: str, user_id: str) -> None:
    _redis().set(f"hunt_owner:{task_id}", user_id, ex=_OWNER_TTL)


def _owner_of(task_id: str) -> str | None:
    try:
        return _redis().get(f"hunt_owner:{task_id}")
    except Exception:
        log.warning("hunt owner lookup failed (Redis down?)")
        return None  # fail closed: nobody gets a result we can't attribute


@router.get("/status")
async def hunt_status(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """Which sources the hunt can use right now, for the page header."""
    from api.hunt.ai import get_ai
    from api.hunt.engine import ALERT_VENDORS, _LABELS, _enabled
    ai = await get_ai(db)
    tools = await _enabled(db, ALERT_VENDORS)
    from api.hunt.handoff import ticket_options
    tickets = await ticket_options(db)
    return {
        "ai": ai is not None,
        "splunk": bool(await _enabled(db, ["splunk"], live=True)),
        "tools": [_LABELS.get(t.vendor.value, t.vendor.value) for t in tools],
        "tickets": {"api": tickets["api"], "email": tickets["email"]},
    }


@router.post("/query")
async def hunt_query(body: HuntQueryRequest, current_user: User = Depends(require_cyber_or_admin)):
    """Ask a plain question; poll /result for the story."""
    from api.core.tasks import hunt_investigate
    task = hunt_investigate.delay(body.query.strip(), body.time_range)
    _remember_owner(task.id, str(current_user.id))
    return {"task_id": task.id}


@router.post("/search")
async def hunt_search(body: HuntSearchRequest, current_user: User = Depends(require_cyber_or_admin)):
    """Run one catalog or hand-edited SPL search, read-only."""
    from api.core.tasks import hunt_run_search
    from api.hunt.spl_guard import vet_spl
    try:
        vet_spl(body.spl)
    except ValueError as exc:
        raise HTTPException(400, f"That search can't run here: {exc}") from exc
    task = hunt_run_search.delay(body.spl, body.time_range)
    _remember_owner(task.id, str(current_user.id))
    return {"task_id": task.id}


class HuntProfileRequest(BaseModel):
    kind: str = Field(pattern="^(user|host|ip)$")
    value: str = Field(min_length=1, max_length=128)
    time_range: str = Field("7d", pattern=_TIME)
    first: str | None = Field(None, max_length=25)
    last: str | None = Field(None, max_length=25)


@router.post("/profile")
async def hunt_profile(body: HuntProfileRequest, current_user: User = Depends(require_cyber_or_admin)):
    """Everything known about one user, computer, or IP."""
    from api.core.tasks import hunt_profile as task_fn
    from api.hunt.profile import check
    try:
        value = check(body.kind, body.value)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    around = {"first": body.first, "last": body.last or body.first} if body.first else None
    task = task_fn.delay(body.kind, value, body.time_range, around)
    _remember_owner(task.id, str(current_user.id))
    return {"task_id": task.id}


@router.get("/result/{task_id}")
async def hunt_result(task_id: str, current_user: User = Depends(require_cyber_or_admin)):
    if _owner_of(task_id) != str(current_user.id):
        raise HTTPException(404)
    from api.core.tasks import celery_app
    result = celery_app.AsyncResult(task_id)
    if result.state == "SUCCESS":
        return {"status": "complete", "result": result.result}
    if result.state == "PROGRESS":
        return {"status": "running", "stage": (result.info or {}).get("stage", "Working")}
    if result.state in ("PENDING", "STARTED", "RETRY", "RECEIVED"):
        return {"status": "pending"}
    return {"status": "failed", "error": "Analysis failed"}


class HuntTicketRequest(BaseModel):
    source: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    issue: int = Field(ge=0, le=20)
    method: str = Field(pattern="^(api|email)$")


@router.post("/ticket")
async def hunt_ticket(body: HuntTicketRequest, current_user: User = Depends(require_cyber_or_admin),
                      db: AsyncSession = Depends(get_session)):
    """Open a ServiceNow ticket for one issue, by API or by email to the inbound address."""
    from api.hunt.handoff import create_ticket, load_issue
    _, issue = await load_issue(db, body.source, body.issue, _owner_of, str(current_user.id))
    out = await create_ticket(db, issue, body.method)
    log.info("hunt ticket via %s by %s: %s", body.method, current_user.username, issue["title"][:80])
    return out


@router.get("/report/{source}/{index}", response_class=HTMLResponse, include_in_schema=False)
async def hunt_report(source: str, index: int, request: Request,
                      current_user: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """A printable incident report for one issue."""
    from datetime import datetime, timezone
    from api.hunt.handoff import load_issue
    from api.main import _get_branding
    if not re.match(r"^[A-Za-z0-9-]{1,64}$", source):
        raise HTTPException(404)
    result, issue = await load_issue(db, source, index, _owner_of, str(current_user.id))
    evidence = [(n, result["lookups"][n - 1]) for n in issue.get("lookups", []) if 0 < n <= len(result.get("lookups", []))]
    from collections import Counter
    by_source = Counter(t.get("source") or "Other" for t in issue.get("timeline", [])).most_common()
    brand = await _get_branding(db)
    return _templates.TemplateResponse(request, "pages/hunt_report.html", {
        "issue": issue, "evidence": evidence, "question": result.get("question", ""),
        "by_source": by_source, "by_source_max": max([c for _, c in by_source] or [1]),
        "sources": result.get("sources", []), "report_id": f"{source[:8]}-{index + 1}".upper(),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "prepared_by": current_user.username, "app_title": brand.get("title", "open-ctem"),
        "org_name": brand.get("org_name"), "accent_color": brand.get("accent_color", "#f5a623"),
    })


@router.get("/watch")
async def hunt_watch(me: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                     show_hidden: bool = False):
    """What the hourly background hunt found, already filtered down to what matters, less what you hid."""
    from api.core import hidden
    from api.hunt.watch import load_watch
    w = await load_watch(db) or {"ran_at": None, "note": "The first check has not run yet.", "result": {"issues": []}}
    gone = (await hidden.load(db, str(me.id)))["watch"]
    issues = (w.get("result") or {}).get("issues") or []
    for i in issues:
        i["hidden"] = i.get("key") in gone
    w["hidden_count"] = sum(i["hidden"] for i in issues)
    if not show_hidden:
        w["result"]["issues"] = [i for i in issues if not i["hidden"]]
    return w


@router.get("/splunk/catalog")
async def get_spl_catalog(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """Ready-made searches plus the ones the AI worked out and saved."""
    from api.hunt.memory import learned_searches
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == "splunk_spl_catalog"))).scalar_one_or_none()
    try:
        catalog = json.loads(row.value) if row and row.value else []
    except ValueError:
        catalog = []
    return {"catalog": catalog, "learned": await learned_searches(db),
            "generated_at": row.updated_at.isoformat() if row and row.updated_at else None}
