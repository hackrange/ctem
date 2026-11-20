"""AI connector -- wraps Anthropic, OpenAI, and custom LLMs."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ai_usage import usage_from_response
from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.ai")

_ANTHROPIC_BASE = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"
_OPENAI_BASE = "https://api.openai.com"


class _RateLimiter:
    """Simple token bucket rate limiter -- shared per vendor instance."""

    def __init__(self, calls_per_minute: int):
        self._rate = calls_per_minute / 60.0  # calls per second
        self._tokens = float(calls_per_minute)
        self._max = float(calls_per_minute)
        self._last_refill = time.monotonic()

    async def acquire(self):
        while True:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._max, self._tokens + elapsed * self._rate)
            self._last_refill = now
            if self._tokens >= 1:
                self._tokens -= 1
                return
            wait = (1 - self._tokens) / self._rate
            await asyncio.sleep(min(wait, 5.0))


# One limiter per vendor type -- class-level so all instances share it
_LIMITERS: dict[str, _RateLimiter] = {}

_DEFAULT_RPM = {
    "anthropic": 50,   # conservative -- well below tier 1 limits
    "openai":    50,
    "custom_ai": 20,
    "ai":        50,
}


def _limiter_for(vendor: str, config: dict) -> _RateLimiter:
    rpm = int(config.get("rate_limit_rpm", _DEFAULT_RPM.get(vendor, 20)))
    key = f"{vendor}:{rpm}"
    if key not in _LIMITERS:
        _LIMITERS[key] = _RateLimiter(rpm)
    return _LIMITERS[key]


class AIConnector(BaseConnector):
    """
    Thin wrapper around AI/LLM providers with rate limiting.
    All production AI calls should go through api/core/tasks.py (Celery async).
    This connector is for config validation and manual test calls only.
    """

    async def test_connection(self) -> bool:
        try:
            vendor = self.vendor.value
            limiter = _limiter_for(vendor, self.config)
            await limiter.acquire()
            async with safe_client() as client:
                if vendor == "openai":
                    resp = await client.get(
                        f"{self._base}/v1/models",
                        headers=self._headers(),
                    )
                elif vendor == "anthropic":
                    # A one-token message proves the key can actually generate
                    resp = await client.post(
                        f"{self._base}/v1/messages",
                        headers=self._headers(),
                        json={
                            "model": self.config.get("model", "claude-haiku-5-5"),
                            "max_tokens": 5,
                            "messages": [{"role": "user", "content": "hi"}],
                        },
                        timeout=20.0,
                    )
                    if resp.status_code == 200:
                        from api.core.ai_usage import record
                        await record("test", vendor, usage_from_response(resp.json(), openai_style=False), True, None,
                                     self.config.get("model"))
                else:
                    # Custom AI: probe base_url root or /v1/models
                    resp = await client.get(
                        f"{self._base}/v1/models",
                        headers=self._headers(),
                        timeout=10.0,
                    )
            return resp.status_code in (200, 400, 401, 404)  # got a response = server is up
        except Exception as e:
            log.warning("AI connector test failed (%s): %s", self.vendor.value, e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        ok = await self.test_connection()
        return 1 if ok else 0

    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 1024,
        model: str | None = None,
        retries: int = 3,
        timeout: float = 60.0,
        purpose: str = "general",
    ) -> str:
        """Single completion with rate limiting, the monthly budget, usage metering, and retries."""
        from api.core import ai_usage
        vendor = self.vendor.value
        limiter = _limiter_for(vendor, self.config)
        used_model = model or self.config.get("model") or _default_model(vendor)
        await ai_usage.guard()  # raises AIBudgetExceeded when this month's limit is used up

        for attempt in range(retries):
            await limiter.acquire()
            started = time.monotonic()
            try:
                result, usage = await self._do_complete(prompt, system, max_tokens, used_model, timeout)
                await ai_usage.record(purpose, vendor, usage, True, int((time.monotonic() - started) * 1000), used_model)
                return result
            except Exception as e:
                await ai_usage.record(purpose, vendor, getattr(e, "usage", None), False,
                                      int((time.monotonic() - started) * 1000), used_model)
                if attempt < retries - 1:
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    log.warning("AI complete attempt %d/%d failed: %s -- retrying in %ds",
                                attempt + 1, retries, e, wait)
                    await asyncio.sleep(wait)
                else:
                    raise
        return ""  # unreachable

    async def _do_complete(self, prompt: str, system: str | None,
                           max_tokens: int, model: str, timeout: float = 60.0) -> tuple[str, dict]:
        vendor = self.vendor.value
        async with safe_client() as client:
            if vendor == "openai" or (vendor == "custom_ai" and self._is_openai_compat):
                messages = []
                if system:
                    messages.append({"role": "system", "content": system})
                messages.append({"role": "user", "content": prompt})
                resp = await client.post(
                    f"{self._base}/v1/chat/completions",
                    headers=self._headers(),
                    json={"model": model, "max_tokens": max_tokens, "messages": messages},
                    timeout=timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                choices = data.get("choices", [{}])
                text = choices[0].get("message", {}).get("content", "") if choices else ""
                return text, usage_from_response(data, openai_style=True)
            else:
                # Anthropic (and anthropic-compat custom)
                body: dict = {
                    "model": model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }
                if system:
                    body["system"] = system
                resp = await client.post(
                    f"{self._base}/v1/messages",
                    headers=self._headers(),
                    json=body,
                    timeout=timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                # Newer models lead with a thinking block; the answer is in the text blocks
                text = "".join(b.get("text", "") for b in data.get("content", [])
                               if isinstance(b, dict) and b.get("type") == "text")
                return text, usage_from_response(data, openai_style=False)

    @property
    def _base(self) -> str:
        url = self.config.get("base_url", "").rstrip("/")
        if url:
            return url
        vendor = self.vendor.value
        if vendor == "openai":
            return _OPENAI_BASE
        return _ANTHROPIC_BASE

    @property
    def _is_openai_compat(self) -> bool:
        """Custom AI vendors that expose an OpenAI-compatible /v1/chat/completions endpoint."""
        return bool(self.config.get("openai_compat", False))

    def _headers(self) -> dict:
        vendor = self.vendor.value
        key = self.config.get("api_key", "")
        extra = {}
        if self.config.get("extra_headers"):
            import json
            try:
                extra = json.loads(self.config["extra_headers"])
            except ValueError:
                log.warning("ignoring extra_headers: not valid JSON")
        if vendor == "anthropic":
            return {
                "x-api-key": key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "Content-Type": "application/json",
                **extra,
            }
        elif vendor == "openai":
            return {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                **extra,
            }
        else:
            # custom_ai -- try Bearer first; fall back to x-api-key if no key style set
            auth_style = self.config.get("auth_style", "bearer")
            if auth_style == "x-api-key":
                return {"x-api-key": key, "Content-Type": "application/json", **extra}
            return {"Authorization": f"Bearer {key}", "Content-Type": "application/json", **extra}


def _default_model(vendor: str) -> str:
    return {
        "anthropic": "claude-haiku-5-5",
        "openai":    "gpt-4o-mini",
        "ai":        "claude-haiku-5-5",
    }.get(vendor, "")


# Register the connector for every AI vendor type.
# Each registration needs a distinct class so the decorator can set .vendor correctly.
@register(Vendor.anthropic)
class _AnthropicConnector(AIConnector):
    pass


@register(Vendor.openai)
class _OpenAIConnector(AIConnector):
    pass


@register(Vendor.custom_ai)
class _CustomAIConnector(AIConnector):
    pass


@register(Vendor.ai)
class _LegacyAIConnector(AIConnector):
    pass
