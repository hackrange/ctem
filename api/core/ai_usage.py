"""AI token metering: usage capture, per-model pricing, and the monthly budget.

Cost is computed when read, so a price change reprices past usage. Claude models use the
built-in list-price table; custom/OpenAI-compatible providers (and unknown models) use the
prices an admin types in. Recording never breaks an AI call.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.ai-usage")

# Anthropic first-party list prices, USD per million tokens (input, output, cache read).
# Cache writes (5-minute TTL) bill at 1.25x input. Source: Anthropic pricing as of 2026-11-03.
PRICE_TABLE_DATE = "2026-11-03"
_CLAUDE = {
    "claude-fable-5-2": ("8", "40", "0.20"),
    "claude-mythos-5-2": ("8", "40", "0.20"),
    "claude-fable-5-1": ("10", "50", None),
    "claude-mythos-5-1": ("10", "50", None),
    "claude-fable-5": ("10", "50", None),
    "claude-opus-5-5": ("4", "20", "0.20"),
    "claude-opus-5": ("5", "25", None),
    "claude-opus-4-8": ("5", "25", None),
    "claude-opus-4-7": ("5", "25", None),
    "claude-opus-4-6": ("5", "25", None),
    "claude-sonnet-5-5": ("2", "10", "0.10"),
    "claude-sonnet-5": ("2", "10", None),
    "claude-sonnet-4-6": ("3", "15", None),
    "claude-haiku-5-5": ("0.10", "0.50", None),
    "claude-haiku-4-5": ("1", "5", None),
}
_DATE_SUFFIX = re.compile(r"-\d{8}$")
_BEDROCK_PREFIX = re.compile(r"^(?:[a-z]{2,4}\.)?anthropic\.")  # anthropic.claude-..., us.anthropic.claude-...
_PRICE_RE = re.compile(r"^(\d{1,6}(\.\d{1,6})?|\.\d{1,6})$")
_MILLION = Decimal(1_000_000)

PRICE_KEYS = ("price_input", "price_output", "price_cache_read", "price_cache_write")
LIMIT_KEYS = ("monthly_cost_limit", "monthly_token_limit")
_PREFIX = "ai."


@dataclass(frozen=True)
class Rates:
    input: Decimal
    output: Decimal
    cache_read: Decimal
    cache_write: Decimal
    source: str  # "claude" | "custom"


class AIBudgetExceeded(RuntimeError):
    """Raised before a call when this month's AI limit is used up."""


def claude_rates(model: str | None) -> Rates | None:
    if not model:
        return None
    m = _DATE_SUFFIX.sub("", _BEDROCK_PREFIX.sub("", model.strip().lower()))
    row = _CLAUDE.get(m)
    if row is None:
        return None
    i, o, cr = (Decimal(x) if x is not None else None for x in row)
    return Rates(i, o, cr if cr is not None else i * Decimal("0.1"), i * Decimal("1.25"), "claude")


def parse_price(raw) -> Decimal | None:
    """'' or None -> None (unset). Raises ValueError on anything that is not a plain price."""
    text = str(raw or "").strip().lstrip("$").strip()
    if not text:
        return None
    if not _PRICE_RE.match(text):
        raise ValueError("Prices must be plain numbers like 3 or 0.25 (per million tokens)")
    try:
        return Decimal(text)
    except InvalidOperation as e:
        raise ValueError("Invalid price") from e


def custom_rates(settings: dict) -> Rates | None:
    vals = {}
    for k in PRICE_KEYS:
        try:
            vals[k] = parse_price(settings.get(k))
        except ValueError:
            vals[k] = None
    if all(v is None for v in vals.values()):
        return None
    z = Decimal(0)
    return Rates(vals["price_input"] or z, vals["price_output"] or z,
                 vals["price_cache_read"] or z, vals["price_cache_write"] or z, "custom")


def rates_for(provider: str | None, model: str | None, settings: dict) -> Rates | None:
    """Anthropic: Claude list prices (custom prices for an unknown model).
    Custom / OpenAI-compatible / Bedrock: the admin's prices (Claude list prices, as an estimate, if none are set)."""
    if provider in (None, "anthropic", "ai"):
        return claude_rates(model) or custom_rates(settings)
    return custom_rates(settings) or claude_rates(model)


def cost(tokens: dict, rates: Rates | None) -> Decimal | None:
    if rates is None:
        return None
    return (Decimal(tokens.get("input", 0)) * rates.input + Decimal(tokens.get("output", 0)) * rates.output
            + Decimal(tokens.get("cache_read", 0)) * rates.cache_read
            + Decimal(tokens.get("cache_write", 0)) * rates.cache_write) / _MILLION


def usage_from_response(body: dict, openai_style: bool) -> dict:
    """Normalize token counts from an Anthropic, OpenAI-compatible, or custom response body."""
    u = body.get("usage") if isinstance(body, dict) else None
    u = u if isinstance(u, dict) else {}

    def n(*keys) -> int:
        for k in keys:
            v = u.get(k)
            if isinstance(v, (int, float)) and v >= 0:
                return int(v)
        return 0

    if openai_style:
        cached = 0
        details = u.get("prompt_tokens_details")
        if isinstance(details, dict) and isinstance(details.get("cached_tokens"), int):
            cached = max(0, details["cached_tokens"])
        choices = body.get("choices") or [{}]
        finish = (choices[0] or {}).get("finish_reason") if isinstance(choices, list) else None
        return {"input": max(0, n("prompt_tokens", "input_tokens") - cached), "output": n("completion_tokens", "output_tokens"),
                "cache_read": cached, "cache_write": 0, "finish": finish, "model": body.get("model")}
    return {"input": n("input_tokens", "prompt_tokens"), "output": n("output_tokens", "completion_tokens"),
            "cache_read": n("cache_read_input_tokens", "cache_read_tokens"),
            "cache_write": n("cache_creation_input_tokens", "cache_write_tokens"),
            "finish": body.get("stop_reason") if isinstance(body, dict) else None,
            "model": body.get("model") if isinstance(body, dict) else None}


def month_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


async def load_settings(db: AsyncSession) -> dict:
    from api.models.settings import AppSetting
    rows = (await db.execute(select(AppSetting).where(AppSetting.key.like(f"{_PREFIX}%")))).scalars()
    return {r.key.removeprefix(_PREFIX): r.value for r in rows}


async def month_to_date(db: AsyncSession, settings: dict | None = None) -> dict:
    """Tokens and cost since the 1st (UTC), summed in SQL per provider/model."""
    from api.models.settings import AIUsage
    settings = settings if settings is not None else await load_settings(db)
    rows = (await db.execute(
        select(AIUsage.provider, AIUsage.model, func.sum(AIUsage.input_tokens), func.sum(AIUsage.output_tokens),
               func.sum(AIUsage.cache_read_tokens), func.sum(AIUsage.cache_write_tokens), func.count())
        .where(AIUsage.at >= month_start()).group_by(AIUsage.provider, AIUsage.model))).all()
    total_cost, tokens, calls, unpriced = Decimal(0), 0, 0, 0
    for provider, model, i, o, cr, cw, c in rows:
        t = {"input": i or 0, "output": o or 0, "cache_read": cr or 0, "cache_write": cw or 0}
        tokens += sum(t.values())
        calls += c
        price = cost(t, rates_for(provider, model, settings))
        if price is None:
            unpriced += c
        else:
            total_cost += price
    return {"cost": total_cost, "tokens": tokens, "calls": calls, "unpriced_calls": unpriced}


_TOKENS_RE = re.compile(r"^\d{1,12}$")


def parse_token_limit(raw) -> Decimal | None:
    """'' or None -> None (no limit). A whole number of tokens, commas allowed; else ValueError."""
    text = str(raw or "").strip().replace(",", "")
    if not text:
        return None
    if not _TOKENS_RE.match(text):
        raise ValueError("Token limit must be a whole number")
    return Decimal(text)


def _limit(settings: dict, key: str) -> Decimal | None:
    parse = parse_token_limit if key == "monthly_token_limit" else parse_price
    try:
        return parse(settings.get(key))  # blank = no limit; 0 = AI off
    except ValueError:
        # A saved cap that no longer parses must not quietly lift the limit: fail closed
        log.warning("AI %s setting is not a valid number; treating it as 0 until an admin fixes it", key)
        return Decimal(0)


async def check_budget(db: AsyncSession) -> None:
    """Raise AIBudgetExceeded when either monthly limit is reached."""
    settings = await load_settings(db)
    cost_cap, token_cap = _limit(settings, "monthly_cost_limit"), _limit(settings, "monthly_token_limit")
    if cost_cap is None and token_cap is None:
        return
    mtd = await month_to_date(db, settings)
    if cost_cap is not None and mtd["cost"] >= cost_cap:
        raise AIBudgetExceeded("This month's AI cost limit has been reached. An admin can raise it under Admin > AI Usage.")
    if token_cap is not None and mtd["tokens"] >= token_cap:
        raise AIBudgetExceeded("This month's AI token limit has been reached. An admin can raise it under Admin > AI Usage.")


def _factory():
    import api.core.db as dbm
    return dbm._session_factory


async def guard() -> None:
    """Budget check in its own session; a broken meter must not block AI (only a reached limit does)."""
    factory = _factory()
    if factory is None:
        return
    try:
        async with factory() as db:
            await check_budget(db)
    except AIBudgetExceeded:
        raise
    except Exception:
        log.warning("AI budget check failed; allowing the call", exc_info=True)


async def record(purpose: str, provider: str, usage: dict | None, ok: bool, duration_ms: int | None,
                 model: str | None = None) -> None:
    """Write one usage row in its own session. Never raises."""
    factory = _factory()
    if factory is None:
        return
    try:
        from api.models.settings import AIUsage
        u = usage or {}
        async with factory() as db:
            db.add(AIUsage(
                at=datetime.now(timezone.utc), purpose=(purpose or "general")[:32], provider=(provider or "?")[:32],
                model=(u.get("model") or model or None) and str(u.get("model") or model)[:128], ok=ok,
                finish=(str(u["finish"])[:32] if u.get("finish") else ("error" if not ok else None)),
                input_tokens=int(u.get("input", 0)), output_tokens=int(u.get("output", 0)),
                cache_read_tokens=int(u.get("cache_read", 0)), cache_write_tokens=int(u.get("cache_write", 0)),
                duration_ms=duration_ms))
            await db.commit()
    except Exception:
        log.warning("could not record AI usage", exc_info=True)
