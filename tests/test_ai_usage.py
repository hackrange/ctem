"""AI metering: pricing, usage capture, monthly limits, and the admin report."""
from __future__ import annotations

import uuid
from decimal import Decimal

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker

from api.core import ai_usage as au


def test_claude_prices_by_model():
    r = au.claude_rates("claude-opus-5-5")
    assert (r.input, r.output, r.cache_read, r.cache_write) == (Decimal("4"), Decimal("20"), Decimal("0.20"), Decimal("5.00"))
    assert au.claude_rates("claude-haiku-4-5-20251001").input == Decimal("1")  # dated ids map to the family
    assert au.claude_rates("claude-sonnet-4-6").cache_read == Decimal("0.3")    # default 0.1x input
    assert au.claude_rates("gpt-unknown") is None and au.claude_rates(None) is None


def test_rates_follow_provider():
    custom = {"price_input": "1.5", "price_output": "6"}
    assert au.rates_for("anthropic", "claude-sonnet-5-5", custom).source == "claude"
    assert au.rates_for("custom_ai", "acme-llm", custom).source == "custom"
    assert au.rates_for("custom_ai", "claude-sonnet-5-5", custom).source == "custom"  # custom API: admin prices win
    assert au.rates_for("custom_ai", "claude-sonnet-5-5", {}).source == "claude"
    assert au.rates_for("openai", "acme-llm", {}) is None  # unpriced, not free


def test_cost_math():
    r = au.claude_rates("claude-opus-5-5")
    c = au.cost({"input": 1_000_000, "output": 500_000, "cache_read": 1_000_000, "cache_write": 0}, r)
    assert c == Decimal("4") + Decimal("10") + Decimal("0.20")


@pytest.mark.parametrize("raw,ok", [("3", True), ("0.25", True), ("$1.50", True), (".5", True), ("", True),
                                    ("-1", False), ("1e3", False), ("abc", False), ("1234567", False)])
def test_parse_price(raw, ok):
    if ok:
        au.parse_price(raw)
    else:
        with pytest.raises(ValueError):
            au.parse_price(raw)


def test_usage_from_both_response_shapes():
    a = au.usage_from_response({"model": "claude-haiku-5-5", "stop_reason": "end_turn", "usage": {
        "input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 50, "cache_creation_input_tokens": 10}}, False)
    assert (a["input"], a["output"], a["cache_read"], a["cache_write"], a["finish"]) == (100, 20, 50, 10, "end_turn")
    o = au.usage_from_response({"model": "acme", "choices": [{"finish_reason": "length"}], "usage": {
        "prompt_tokens": 120, "completion_tokens": 30, "prompt_tokens_details": {"cached_tokens": 20}}}, True)
    assert (o["input"], o["output"], o["cache_read"], o["finish"]) == (100, 30, 20, "length")
    assert au.usage_from_response({"usage": "junk"}, False)["input"] == 0


@pytest_asyncio.fixture
async def metered(db, monkeypatch):
    factory = async_sessionmaker(db.bind, expire_on_commit=False)
    monkeypatch.setattr(au, "_factory", lambda: factory)
    yield db
    await _set(db, monthly_cost_limit="", monthly_token_limit="")


async def _set(db, **kv):
    from sqlalchemy import select

    from api.models.settings import AppSetting
    for k, v in kv.items():
        row = (await db.execute(select(AppSetting).where(AppSetting.key == f"ai.{k}"))).scalar_one_or_none()
        if row is None:
            db.add(AppSetting(key=f"ai.{k}", value=v))
        else:
            row.value = v
    await db.commit()


@pytest.mark.asyncio
async def test_record_and_budget(metered):
    model = f"acme-{uuid.uuid4().hex[:6]}"
    await au.record("hunt", "custom_ai", {"input": 10, "output": 5, "model": model}, True, 12)
    await au.guard()  # no limits: fine
    await _set(metered, monthly_token_limit="1")
    with pytest.raises(au.AIBudgetExceeded):
        await au.guard()
    await _set(metered, monthly_token_limit="", monthly_cost_limit="0")  # 0 turns AI off
    with pytest.raises(au.AIBudgetExceeded):
        await au.guard()


@pytest.mark.asyncio
async def test_connector_meters_and_respects_limit(metered, monkeypatch):
    from sqlalchemy import select

    from api.integrations import ai_connector
    from api.integrations.base import get_connector
    from api.models.settings import AIUsage

    model = f"acme-{uuid.uuid4().hex[:6]}"
    calls = []

    def fake_client(**_):
        def handler(request):
            calls.append(1)
            return httpx.Response(200, json={"model": model, "stop_reason": "end_turn",
                                             "content": [{"type": "text", "text": "hi"}],
                                             "usage": {"input_tokens": 7, "output_tokens": 3}})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(ai_connector, "safe_client", fake_client)
    ai = get_connector("anthropic", {"api_key": "example-not-a-key", "model": model})
    assert await ai.complete("q", purpose="hunt") == "hi"
    row = (await metered.execute(select(AIUsage).where(AIUsage.model == model))).scalar_one()
    assert (row.purpose, row.input_tokens, row.output_tokens, row.ok) == ("hunt", 7, 3, True)

    await _set(metered, monthly_cost_limit="0")
    with pytest.raises(au.AIBudgetExceeded):
        await ai.complete("q", purpose="hunt")
    assert len(calls) == 1  # blocked before any request went out


@pytest.mark.asyncio
async def test_admin_report_and_settings(client_admin, metered):
    from sqlalchemy import select

    from api.models.settings import AuditLog

    await au.record("threat_analysis", "anthropic", {"input": 1_000_000, "output": 0, "model": "claude-opus-5-5"}, True, 5)
    rep = (await client_admin.get("/api/v1/admin/ai-usage", params={"days": 7})).json()
    opus = [r for r in rep["by_model"] if r["model"] == "claude-opus-5-5"][0]
    assert opus["price_source"] == "claude" and opus["cost"] >= 4.0
    assert rep["month"]["cost"] >= 4.0 and rep["claude_prices"]["models"]

    bad = await client_admin.put("/api/v1/admin/ai-usage/settings", json={"price_input": "=1+1"})
    assert bad.status_code == 400
    ok = await client_admin.put("/api/v1/admin/ai-usage/settings",
                                json={"price_input": "3", "price_output": "15", "monthly_cost_limit": "250"})
    assert ok.status_code == 200 and set(ok.json()["changed"]) == {"price_input", "price_output", "monthly_cost_limit"}
    audit = (await metered.execute(select(AuditLog).where(AuditLog.action == "ai_usage.settings")
                                   .order_by(AuditLog.created_at.desc()))).scalars().first()
    assert "price_input" in audit.detail and "3" not in audit.detail.replace("price_input", "")
    rep = (await client_admin.get("/api/v1/admin/ai-usage")).json()
    assert rep["settings"]["monthly_cost_limit"] == "250" and rep["month"]["cost_limit"] == 250.0
    await _set(metered, price_input="", price_output="")


@pytest.mark.asyncio
async def test_usage_is_admin_only(client_cyber):
    assert (await client_cyber.get("/api/v1/admin/ai-usage")).status_code == 403
    assert (await client_cyber.put("/api/v1/admin/ai-usage/settings", json={})).status_code == 403
