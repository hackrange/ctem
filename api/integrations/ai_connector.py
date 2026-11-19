"""AI connector -- wraps Anthropic API with SSRF-safe transport and token accounting."""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.ai")

_ANTHROPIC_BASE = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"


@register(Vendor.ai)
class AIConnector(BaseConnector):
    """
    Thin wrapper around Anthropic Claude.
    All actual AI calls should go through api/core/tasks.py (Celery async).
    This connector is for config validation and manual test calls only.
    """

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{_ANTHROPIC_BASE}/v1/models",
                    headers=self._headers(),
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("AI connector test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        """No data sync for AI -- just validates credentials are live."""
        ok = await self.test_connection()
        return 1 if ok else 0

    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 1024,
        model: str | None = None,
    ) -> str:
        """Single completion call. Use only from Celery tasks -- never on hot path."""
        body = {
            "model": model or self.config.get("model", "claude-haiku-5-5"),
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system

        async with safe_client() as client:
            resp = await client.post(
                f"{_ANTHROPIC_BASE}/v1/messages",
                headers=self._headers(),
                json=body,
                timeout=60.0,
            )
        resp.raise_for_status()
        content = resp.json().get("content", [{}])
        return content[0].get("text", "") if content else ""

    def _headers(self) -> dict:
        return {
            "x-api-key": self.config["api_key"],
            "anthropic-version": _ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }
