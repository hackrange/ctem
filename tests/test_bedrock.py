"""Claude on Amazon Bedrock: config checks, the SDK client, metering, provider choice, and the admin routes."""
from __future__ import annotations

import functools
import json
import uuid

import httpx2
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from api.core import ai_usage as au
from api.integrations import ai_bedrock as bd

GOOD = {"aws_region": "us-east-1", "auth_mode": "access_key", "aws_access_key_id": "AKIAEXAMPLEEXAMPLE00",
        "aws_secret_access_key": "example-not-a-secret", "model": "anthropic.claude-sonnet-5-5"}


@pytest.mark.parametrize("change,ok", [
    ({}, True),
    ({"aws_region": "us-gov-west-1"}, True),
    ({"model": "us.anthropic.claude-opus-5-5"}, True),
    ({"auth_mode": "default"}, True),
    ({"aws_region": "169.254.169.254"}, False),
    ({"aws_region": "us-east-1.evil.example"}, False),
    ({"auth_mode": "root"}, False),
    ({"model": "claude-sonnet-5-5"}, False),          # Bedrock IDs carry the anthropic. prefix
    ({"model": "anthropic.sonnet/../x"}, False),
    ({"aws_access_key_id": "not a key"}, False),
    ({"api_key": {"k": 1}}, False),
    ({"rate_limit_rpm": "fast"}, False),
])
def test_validate_config(change, ok):
    conf = {**GOOD, **change}
    if ok:
        bd.validate_config(conf)
    else:
        with pytest.raises(bd.BedrockConfigError):
            bd.validate_config(conf)


def test_ready_needs_what_the_sign_in_needs():
    assert bd.ready(GOOD)
    assert not bd.ready({**GOOD, "aws_secret_access_key": ""})
    assert not bd.ready({**GOOD, "auth_mode": "api_key"}) and bd.ready({**GOOD, "auth_mode": "api_key", "api_key": "k"})
    assert bd.ready({"aws_region": "eu-west-1", "auth_mode": "default"})
    assert not bd.ready({"auth_mode": "default"})


def test_client_endpoint_comes_from_the_region_only():
    c = bd._client(GOOD, 10.0)
    assert str(c.base_url) == "https://bedrock-mantle.us-east-1.api.aws/anthropic/"
    assert c.aws_access_key == GOOD["aws_access_key_id"] and c.max_retries == 0
    assert bd._client({**GOOD, "auth_mode": "api_key", "api_key": "k"}, 10.0).api_key == "k"
    with pytest.raises(bd.BedrockConfigError):
        bd._client({**GOOD, "aws_region": "localhost"}, 10.0)


def test_bedrock_ids_get_claude_prices():
    assert au.claude_rates("anthropic.claude-opus-5-5").input == au.claude_rates("claude-opus-5-5").input
    assert au.claude_rates("us.anthropic.claude-haiku-5-5") is not None
    assert au.rates_for("bedrock", "anthropic.claude-sonnet-5-5", {}).source == "claude"
    assert au.rates_for("bedrock", "anthropic.claude-sonnet-5-5", {"price_input": "2.5"}).source == "custom"


@pytest.mark.asyncio
async def test_complete_signs_meters_and_reads_text(db, monkeypatch):
    from sqlalchemy import select

    from api.integrations.base import get_connector
    from api.models.settings import AIUsage

    factory = async_sessionmaker(db.bind, expire_on_commit=False)
    monkeypatch.setattr(au, "_factory", lambda: factory)
    model = f"anthropic.claude-sonnet-5-5-{uuid.uuid4().hex[:6]}"[:60]
    seen = []

    def handler(request: httpx2.Request):
        seen.append(request)
        return httpx2.Response(200, json={
            "id": "msg_1", "type": "message", "role": "assistant", "model": model, "stop_reason": "end_turn",
            "content": [{"type": "thinking", "thinking": "", "signature": "s"}, {"type": "text", "text": "hello"}],
            "usage": {"input_tokens": 9, "output_tokens": 4}})

    mock = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    monkeypatch.setattr(bd, "_client", functools.partial(bd._client, http_client=mock))
    ai = get_connector("bedrock", {**GOOD, "model": model})
    assert await ai.complete("q", system="be brief", purpose="hunt") == "hello"
    req = seen[0]
    assert req.url.host == "bedrock-mantle.us-east-1.api.aws" and req.url.path == "/anthropic/v1/messages"
    assert req.headers["authorization"].startswith("AWS4-HMAC-SHA256")   # SigV4, not a bearer key
    body = json.loads(req.content)
    assert body["model"] == model and body["system"] == "be brief"
    row = (await db.execute(select(AIUsage).where(AIUsage.model == model))).scalar_one()
    assert (row.provider, row.input_tokens, row.output_tokens, row.ok) == ("bedrock", 9, 4, True)


@pytest.mark.asyncio
async def test_failed_test_connection_is_false(monkeypatch):
    def handler(_):
        return httpx2.Response(403, json={"type": "error", "error": {"type": "permission_error", "message": "no"}})
    mock = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    monkeypatch.setattr(bd, "_client", functools.partial(bd._client, http_client=mock))
    assert await bd.BedrockConnector(GOOD).test_connection() is False
    assert await bd.BedrockConnector({"auth_mode": "default"}).test_connection() is False   # no region: no call


def test_draft_errors_name_the_problem():
    import anthropic

    from api.rules.ai_draft import _why
    resp = httpx2.Response(403, request=httpx2.Request("POST", "https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages"))
    exc = anthropic.PermissionDeniedError("no", response=resp, body=None)
    assert "AWS credentials" in _why(exc)


@pytest.mark.asyncio
async def test_get_ai_uses_a_ready_bedrock_integration(db):
    from api.hunt.ai import get_ai
    from api.models.integration import IntegrationConfig, Vendor
    half = IntegrationConfig(vendor=Vendor.bedrock, name="half", is_enabled=True, config={"aws_region": "us-east-1"})
    db.add(half)
    await db.commit()
    first = await get_ai(db)
    assert not isinstance(first, bd.BedrockConnector)          # no credentials yet: skipped
    full = IntegrationConfig(vendor=Vendor.bedrock, name="full", is_enabled=True, config=GOOD)
    db.add(full)
    await db.commit()
    try:
        ai = await get_ai(db)
        if first is None:       # no other AI integration in this test database
            assert isinstance(ai, bd.BedrockConnector)
    finally:
        await db.delete(half)
        await db.delete(full)
        await db.commit()


@pytest.mark.asyncio
async def test_routes_validate_and_mask(client_admin):
    bad = await client_admin.post("/api/v1/integrations", json={
        "vendor": "bedrock", "name": "ACME Bedrock", "is_enabled": False, "config": {**GOOD, "aws_region": "10.0.0.1"}})
    assert bad.status_code == 400
    url = await client_admin.post("/api/v1/integrations", json={
        "vendor": "bedrock", "name": "ACME Bedrock", "is_enabled": False,
        "config": {**GOOD, "base_url": "https://198.51.100.7"}})
    assert url.status_code == 400
    r = await client_admin.post("/api/v1/integrations", json={
        "vendor": "bedrock", "name": "ACME Bedrock", "is_enabled": False, "config": GOOD})
    assert r.status_code == 200
    d = r.json()
    assert d["config"]["aws_secret_access_key"] == "__REDACTED__" and d["config"]["aws_region"] == "us-east-1"
    up = await client_admin.put(f"/api/v1/integrations/{d['id']}", json={"config": {
        **GOOD, "aws_secret_access_key": "__REDACTED__", "model": "claude-opus-5-5"}})
    assert up.status_code == 400
    ok = await client_admin.put(f"/api/v1/integrations/{d['id']}", json={"config": {
        **GOOD, "aws_secret_access_key": "__REDACTED__", "aws_region": "eu-west-1"}})
    assert ok.status_code == 200 and ok.json()["config"]["aws_region"] == "eu-west-1"
    assert (await client_admin.delete(f"/api/v1/integrations/{d['id']}")).status_code in (200, 204)
