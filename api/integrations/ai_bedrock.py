"""Claude on Amazon Bedrock, through the Anthropic SDK's Bedrock (Mantle) client.

The endpoint is always https://bedrock-mantle.<region>.api.aws/anthropic, built from an allow-listed
region, so there is no admin-supplied URL to point anywhere else. Sign-in is one of:
  access_key  an IAM access key pair (least privilege: invoke only the chosen Claude models)
  api_key     a Bedrock API key
  default     the server's own AWS credentials (instance role, environment, ~/.aws)
"""
from __future__ import annotations

import logging
import re

from api.core.ai_usage import usage_from_response
from api.integrations.ai_connector import AIConnector
from api.integrations.base import register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.ai")

AUTH_MODES = ("access_key", "api_key", "default")
DEFAULT_MODEL = "anthropic.claude-opus-5-5"
MODELS = ("anthropic.claude-opus-5-5", "anthropic.claude-sonnet-5-5", "anthropic.claude-haiku-5-5",
          "anthropic.claude-fable-5-2", "anthropic.claude-opus-5", "anthropic.claude-sonnet-5")
_REGION = re.compile(r"^(?:us|eu|ap|ca|sa|me|af|il|mx)(?:-gov)?-[a-z]+-\d$")
_MODEL = re.compile(r"^(?:[a-z]{2,4}\.)?anthropic\.[a-z0-9][a-z0-9.:-]{2,100}$")
_KEY_ID = re.compile(r"^[A-Z0-9]{16,128}$")


class BedrockConfigError(ValueError):
    """A config value that can't be used; the message is safe to show an admin."""


def validate_config(config: dict) -> None:
    """Server-side check of a Bedrock integration's settings before they are saved."""
    if not _REGION.match(str(config.get("aws_region") or "")):
        raise BedrockConfigError("Pick an AWS region such as us-east-1")
    mode = config.get("auth_mode") or "access_key"
    if mode not in AUTH_MODES:
        raise BedrockConfigError("Sign-in must be an access key, a Bedrock API key, or the server's AWS credentials")
    model = config.get("model")
    if model and not _MODEL.match(str(model)):
        raise BedrockConfigError("Bedrock model IDs look like anthropic.claude-sonnet-5-5")
    key_id = config.get("aws_access_key_id")
    if mode == "access_key" and key_id and not _KEY_ID.match(str(key_id)):
        raise BedrockConfigError("That doesn't look like an AWS access key ID")
    for k in ("aws_access_key_id", "aws_secret_access_key", "api_key"):
        v = config.get(k)
        if v is not None and (not isinstance(v, str) or len(v) > 2048):
            raise BedrockConfigError("Credentials must be plain text")
    for k in ("rate_limit_rpm",):
        if config.get(k) not in (None, "") and not str(config[k]).isdigit():
            raise BedrockConfigError("Rate limit must be a whole number of calls per minute")


def ready(config: dict) -> bool:
    """Enough to try a call: a region, plus the credentials the chosen sign-in needs."""
    if not _REGION.match(str(config.get("aws_region") or "")):
        return False
    mode = config.get("auth_mode") or "access_key"
    if mode == "access_key":
        return bool(config.get("aws_access_key_id") and config.get("aws_secret_access_key"))
    if mode == "api_key":
        return bool(config.get("api_key"))
    return mode == "default"


def _client(config: dict, timeout: float, http_client=None):
    from anthropic import AsyncAnthropicBedrockMantle
    region = str(config.get("aws_region") or "")
    if not _REGION.match(region):
        raise BedrockConfigError("No valid AWS region configured")
    kw: dict = {"aws_region": region, "base_url": f"https://bedrock-mantle.{region}.api.aws/anthropic",
                "timeout": timeout, "max_retries": 0,   # AIConnector.complete owns retries and backoff
                "http_client": http_client}
    mode = config.get("auth_mode") or "access_key"
    if mode == "access_key":
        kw["aws_access_key"] = config.get("aws_access_key_id") or None
        kw["aws_secret_key"] = config.get("aws_secret_access_key") or None
    elif mode == "api_key":
        kw["api_key"] = config.get("api_key") or None
    return AsyncAnthropicBedrockMantle(**kw)


@register(Vendor.bedrock)
class BedrockConnector(AIConnector):

    async def test_connection(self) -> bool:
        """A tiny real message: proves the region, the credentials and access to the model together."""
        from api.core import ai_usage
        if not ready(self.config):
            return False
        model = self.config.get("model") or DEFAULT_MODEL
        try:
            text, usage = await self._do_complete("hi", None, 16, model, 30.0)
            await ai_usage.record("test", "bedrock", usage, True, None, model)
            return True
        except Exception as exc:  # noqa: BLE001 -- reported as a failed test; the reason is logged, never shown
            log.warning("Bedrock test failed: %s (HTTP %s)", type(exc).__name__, getattr(exc, "status_code", "-"))
            return False

    async def _do_complete(self, prompt: str, system: str | None, max_tokens: int, model: str,
                           timeout: float = 60.0) -> tuple[str, dict]:
        if not _MODEL.match(model or ""):
            model = DEFAULT_MODEL
        kw: dict = {"model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}]}
        if system:
            kw["system"] = system
        async with _client(self.config, timeout) as client:
            msg = await client.messages.create(**kw)
        data = msg.to_dict()
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if isinstance(b, dict) and b.get("type") == "text")
        return text, usage_from_response(data, openai_style=False)
