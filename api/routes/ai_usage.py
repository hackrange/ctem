"""Admin: AI token usage, cost, custom prices, and the monthly limit."""
from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core import ai_usage as au
from api.core.db import get_session
from api.models.settings import AIUsage, AppSetting, AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/admin/ai-usage", tags=["admin"])


def _money(d: Decimal | None) -> float | None:
    return None if d is None else float(d.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))


def _num(v) -> str | None:
    return None if v is None else str(v)


@router.get("")
async def usage_report(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
    days: int = Query(30, ge=1, le=366),
):
    settings = await au.load_settings(db)
    since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    day = func.date(AIUsage.at)
    rows = (await db.execute(
        select(day, AIUsage.purpose, AIUsage.provider, AIUsage.model, func.count(),
               func.sum(case((AIUsage.ok.is_(False), 1), else_=0)),
               func.sum(AIUsage.input_tokens), func.sum(AIUsage.output_tokens),
               func.sum(AIUsage.cache_read_tokens), func.sum(AIUsage.cache_write_tokens))
        .where(AIUsage.at >= since).group_by(day, AIUsage.purpose, AIUsage.provider, AIUsage.model))).all()

    daily: dict[str, dict] = {}
    by_model: dict[tuple, dict] = {}
    by_purpose: dict[str, dict] = {}
    totals = _bucket()
    for d, purpose, provider, model, calls, failed, i, o, cr, cw in rows:
        t = {"input": int(i or 0), "output": int(o or 0), "cache_read": int(cr or 0), "cache_write": int(cw or 0)}
        rates = au.rates_for(provider, model, settings)
        c = au.cost(t, rates)
        for bucket in (daily.setdefault(str(d), _bucket()), by_model.setdefault((provider, model), _bucket()),
                       by_purpose.setdefault(purpose, _bucket()), totals):
            _add(bucket, calls, failed, t, c)
        by_model[(provider, model)]["rates"] = rates

    mtd = await au.month_to_date(db, settings)
    now = datetime.now(timezone.utc)
    dim = calendar.monthrange(now.year, now.month)[1]
    elapsed = max(1, now.day)
    cost_cap = au._limit(settings, "monthly_cost_limit")
    token_cap = au._limit(settings, "monthly_token_limit")
    return {
        "days": days,
        "currency": "$",
        "totals": _out(totals),
        "daily": [{"date": k, **_out(v)} for k, v in sorted(daily.items())],
        "by_model": sorted(({"provider": p, "model": m, **_out(v), "price_source": v["rates"].source if v.get("rates") else None}
                            for (p, m), v in by_model.items()), key=lambda r: -(r["cost"] or 0) - r["tokens"] / 1e12),
        "by_purpose": sorted(({"purpose": k, **_out(v)} for k, v in by_purpose.items()), key=lambda r: -r["tokens"]),
        "month": {
            "cost": _money(mtd["cost"]), "tokens": mtd["tokens"], "calls": mtd["calls"],
            "unpriced_calls": mtd["unpriced_calls"],
            "forecast_cost": _money(mtd["cost"] / elapsed * dim), "forecast_tokens": int(mtd["tokens"] / elapsed * dim),
            "cost_limit": _money(cost_cap), "token_limit": int(token_cap) if token_cap is not None else None,
            "cost_percent": _pct(mtd["cost"], cost_cap), "token_percent": _pct(Decimal(mtd["tokens"]), token_cap),
            "resets": (now.replace(day=dim) + timedelta(days=1)).date().isoformat(),
        },
        "settings": {k: settings.get(k) or "" for k in au.PRICE_KEYS + au.LIMIT_KEYS},
        "claude_prices": {"as_of": au.PRICE_TABLE_DATE, "models": [
            {"model": m, "input": _num(r.input), "output": _num(r.output), "cache_read": _num(r.cache_read),
             "cache_write": _num(r.cache_write)} for m in au._CLAUDE if (r := au.claude_rates(m))]},
    }


def _bucket() -> dict:
    return {"calls": 0, "failed": 0, "input": 0, "output": 0, "cache_read": 0, "cache_write": 0,
            "cost": Decimal(0), "unpriced": 0}


def _add(b: dict, calls, failed, t: dict, c: Decimal | None) -> None:
    b["calls"] += int(calls or 0)
    b["failed"] += int(failed or 0)
    for k, v in t.items():
        b[k] += v
    if c is None:
        b["unpriced"] += int(calls or 0)
    else:
        b["cost"] += c


def _out(b: dict) -> dict:
    tokens = b["input"] + b["output"] + b["cache_read"] + b["cache_write"]
    return {"calls": b["calls"], "failed": b["failed"], "input": b["input"], "output": b["output"],
            "cache_read": b["cache_read"], "cache_write": b["cache_write"], "tokens": tokens,
            "cost": _money(b["cost"]) if b["calls"] > b["unpriced"] else None, "unpriced_calls": b["unpriced"]}


def _pct(used: Decimal, cap: Decimal | None) -> float | None:
    if cap is None:
        return None
    if cap == 0:
        return 100.0
    return round(float(used / cap * 100), 1)


class UsageSettings(BaseModel):
    price_input: str = Field("", max_length=16)
    price_output: str = Field("", max_length=16)
    price_cache_read: str = Field("", max_length=16)
    price_cache_write: str = Field("", max_length=16)
    monthly_cost_limit: str = Field("", max_length=16)
    monthly_token_limit: str = Field("", max_length=16)


@router.put("/settings")
async def save_settings(
    body: UsageSettings,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    values = body.model_dump()
    try:
        for k in au.PRICE_KEYS + ("monthly_cost_limit",):
            au.parse_price(values[k])
    except ValueError as e:
        raise HTTPException(400, detail=str(e)) from None
    try:
        au.parse_token_limit(values["monthly_token_limit"])   # the same parser the limit is enforced with
    except ValueError as e:
        raise HTTPException(400, detail=str(e)) from None
    values["monthly_token_limit"] = values["monthly_token_limit"].strip().replace(",", "")

    existing = {r.key: r for r in (await db.execute(
        select(AppSetting).where(AppSetting.key.in_([f"ai.{k}" for k in values])))).scalars()}
    changed = []
    for k, v in values.items():
        v = v.strip().lstrip("$").strip()
        row = existing.get(f"ai.{k}")
        if (row.value if row else "") == v:
            continue
        if row is None:
            db.add(AppSetting(key=f"ai.{k}", value=v, is_sensitive=False))
        else:
            row.value = v
        changed.append(k)
    if changed:
        # Names only; values live in the settings table
        db.add(AuditLog(actor_user_id=str(current_user.id), actor_username=current_user.username,
                        action="ai_usage.settings", resource_type="settings", resource_id="ai",
                        detail="changed: " + ", ".join(changed)))
    await db.commit()
    return {"saved": True, "changed": changed}
