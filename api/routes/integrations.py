"""Integration CRUD: configure connectors, trigger syncs, view status."""
from __future__ import annotations

import logging
import re
import uuid
from urllib.parse import urlparse

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.integrations")

from api.auth.middleware import get_current_user
from api.auth.rbac import require_admin, require_cyber_or_admin
from api.core.db import get_session
from api.models.integration import IntegrationConfig, SyncJob, Vendor
from api.models.user import User


def _validate_base_url(url: str) -> None:
    """Reject non-http(s) or SSRF-unsafe destinations. Respects SSRF_BYPASS_HOSTS."""
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise HTTPException(400, "base_url must use http or https")
    from api.core.ssrf import SSRFBlocked, SSRFUnresolvable, _resolve_and_validate
    try:
        _resolve_and_validate(parsed.hostname or "")
    except SSRFUnresolvable:
        pass  # not in DNS yet; safe_client re-checks on every request
    except SSRFBlocked as exc:
        log.warning("rejected base_url: %s", exc)
        raise HTTPException(400, "base_url is not an allowed destination") from exc


def _check_vendor_config(vendor: Vendor, config: dict) -> None:
    """Per-vendor checks before a config is stored. Bedrock has no URL at all: the region picks the endpoint."""
    if vendor != Vendor.bedrock:
        return
    from api.integrations.ai_bedrock import BedrockConfigError, validate_config
    if config.get("base_url"):
        raise HTTPException(400, "Bedrock doesn't take a base URL; pick the AWS region instead")
    try:
        validate_config(config)
    except BedrockConfigError as exc:
        raise HTTPException(400, str(exc)) from exc

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("")
async def list_integrations(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).order_by(IntegrationConfig.vendor))
    return {"integrations": [_summary(i) for i in result.scalars()]}


@router.get("/vendors")
async def list_vendors(
    _: User = Depends(require_cyber_or_admin),
):
    """All vendor slugs supported by this instance -- for the add-integration modal."""
    return {
        "vendors": [
            {"slug": v.value, "label": v.value.replace("_", " ").title()}
            for v in Vendor
        ]
    }


# Known fallback models per vendor -- shown before fetching live list
_KNOWN_MODELS: dict[str, list[str]] = {
    "anthropic": [
        "claude-opus-5-5",
        "claude-sonnet-5-5",
        "claude-haiku-5-5",
        "claude-fable-5-2",
        "claude-opus-5",
        "claude-sonnet-5",
        "claude-haiku-4-5",
        "claude-sonnet-4-6",
    ],
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "o1",
        "o1-mini",
        "o3-mini",
        "gpt-4-turbo",
        "gpt-3.5-turbo",
    ],
}

_ANTHROPIC_HEADERS = "2023-06-01"


class VendorModelsRequest(BaseModel):
    vendor: str
    api_key: str
    base_url: str = ""


@router.post("/vendor-models")
async def fetch_vendor_models(
    body: VendorModelsRequest,
    _: User = Depends(require_admin),
):
    """Fetch available model IDs directly from the AI provider using the supplied key."""
    vendor = body.vendor.lower()
    if vendor not in ("anthropic", "openai", "custom_ai", "ai"):
        return {"models": _KNOWN_MODELS.get(vendor, [])}

    base = (body.base_url or "").rstrip("/")
    if base:
        _validate_base_url(base)
    else:
        base = "https://api.anthropic.com" if vendor in ("anthropic", "ai") else "https://api.openai.com"

    if vendor in ("anthropic", "ai"):
        url = f"{base}/v1/models"
        headers = {
            "x-api-key": body.api_key,
            "anthropic-version": _ANTHROPIC_HEADERS,
        }
    else:
        url = f"{base}/v1/models"
        headers = {"Authorization": f"Bearer {body.api_key}"}

    from api.core.ssrf import safe_client
    try:
        async with safe_client(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return {"models": _KNOWN_MODELS.get(vendor, []), "error": f"API returned {resp.status_code}"}
        data = resp.json()
        # Anthropic: {"data": [{"id": ...}]} -- OpenAI same shape
        models_raw = data.get("data", [])
        models = sorted(
            m["id"] for m in models_raw if isinstance(m, dict) and m.get("id")
        )
        return {"models": models or _KNOWN_MODELS.get(vendor, [])}
    except Exception as exc:
        log.warning("vendor-models fetch failed for %s: %s", vendor, exc)
        return {"models": _KNOWN_MODELS.get(vendor, []), "error": "Could not reach the provider"}


@router.post("")
async def create_integration(
    body: CreateIntegrationRequest,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    if body.config.get("base_url"):
        _validate_base_url(body.config["base_url"])
    _check_vendor_config(body.vendor, body.config)
    cfg = IntegrationConfig(
        vendor=body.vendor,
        name=body.name,
        is_enabled=body.is_enabled,
        config=body.config,
        sync_schedule=body.sync_schedule,
    )
    db.add(cfg)
    await db.commit()
    return _summary(cfg)


@router.get("/{integration_id}")
async def get_integration(
    integration_id: uuid.UUID,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == str(integration_id)))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    return _summary(cfg)


@router.put("/{integration_id}")
async def update_integration(
    integration_id: uuid.UUID,
    body: UpdateIntegrationRequest,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == str(integration_id)))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    if body.name is not None:
        cfg.name = body.name
    if body.is_enabled is not None:
        cfg.is_enabled = body.is_enabled
    if body.config is not None:
        if body.config.get("base_url"):
            _validate_base_url(body.config["base_url"])
        # Merge: keep existing secret values when the client sends back the redacted sentinel
        existing = dict(cfg.config or {})
        moved = any(
            k in body.config and body.config[k] != existing.get(k)
            for k in _ENDPOINT_KEYS
        )
        if moved and "__REDACTED__" in body.config.values():
            raise HTTPException(400, "Re-enter credentials when changing the endpoint")
        merged = {
            k: existing.get(k, v) if v == "__REDACTED__" else v
            for k, v in body.config.items()
            if v not in ("", None)
        }
        _check_vendor_config(cfg.vendor, merged)
        if existing.get("mode") == "collector":
            # Collector wiring is server-owned; the edit form doesn't know about it
            merged["mode"], merged["collector"] = "collector", existing.get("collector")
        cfg.config = merged
    if body.sync_schedule is not None:
        cfg.sync_schedule = body.sync_schedule
    await db.commit()
    return _summary(cfg)


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == str(integration_id)))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    await db.delete(cfg)
    await db.commit()
    return {"deleted": True}


@router.post("/{integration_id}/sync")
async def trigger_sync(
    integration_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == str(integration_id), IntegrationConfig.is_enabled == True))  # noqa: E712
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    from api.integrations.base import is_collector_fed
    if is_collector_fed(cfg):
        raise HTTPException(409, detail="This integration is fed by an on-prem collector; run open-ctem-collector run-now on that box")
    from api.core.tasks import sync_integration
    task = sync_integration.delay(str(integration_id))
    return {"task_id": task.id, "status": "queued"}


@router.post("/{integration_id}/test")
async def test_connection(
    integration_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    from datetime import datetime, timezone

    from api.integrations.base import get_connector
    from api.models.integration import SyncStatus

    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == str(integration_id)))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    try:
        from api.integrations.base import is_collector_fed
        if is_collector_fed(cfg):
            ok = await _collector_recent(cfg, db)
        else:
            connector = get_connector(cfg.vendor.value, cfg.config or {})
            ok = await connector.test_connection()
    except Exception as exc:
        log.warning("test_connection failed for %s: %s", cfg.vendor.value, exc)
        ok = False
    # Persist result so the card chip updates
    cfg.last_sync_at = datetime.now(timezone.utc)
    cfg.last_sync_status = SyncStatus.success if ok else SyncStatus.failed
    await db.commit()
    return {"connected": ok}


@router.get("/{integration_id}/jobs")
async def list_sync_jobs(
    integration_id: uuid.UUID,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(SyncJob)
        .where(SyncJob.integration_id == str(integration_id))
        .order_by(SyncJob.created_at.desc())
        .limit(50)
    )
    jobs = result.scalars().all()
    return {"jobs": [{"id": str(j.id), "status": j.status.value, "started": j.started_at.isoformat() if j.started_at else None, "records": j.records_imported, "error": j.error_message} for j in jobs]}


async def _collector_recent(cfg: IntegrationConfig, db: AsyncSession) -> bool:
    """Collector-fed means 'connected' is 'a collector owning this checked in within a day'."""
    from datetime import datetime, timedelta, timezone

    from api.models.collector import CollectorToken
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    toks = (await db.execute(select(CollectorToken).where(CollectorToken.is_active == True))).scalars()  # noqa: E712
    for t in toks:
        seen = t.last_seen
        if seen is not None and seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        if str(cfg.id) in (t.integration_ids or []) and seen and seen >= cutoff:
            return True
    return False


_SECRET_RE = re.compile(r"(secret|passw|pass$|token|api_?key|private_?key|credential)", re.I)
_ENDPOINT_KEYS = ("base_url", "url", "host", "server", "instance_url", "tenant_url", "endpoint")


def _mask_config(config: dict) -> dict:
    """Return config with secret fields replaced by a sentinel."""
    return {
        k: "__REDACTED__" if _SECRET_RE.search(k) and v else v
        for k, v in (config or {}).items()
    }


def _summary(cfg: IntegrationConfig) -> dict:
    return {
        "id": str(cfg.id),
        "vendor": cfg.vendor.value,
        "name": cfg.name,
        "is_enabled": cfg.is_enabled,
        "last_sync_at": cfg.last_sync_at.isoformat() if cfg.last_sync_at else None,
        "last_sync_status": cfg.last_sync_status.value if cfg.last_sync_status else None,
        "sync_schedule": cfg.sync_schedule,
        "config": _mask_config(cfg.config),
    }


def _check_cron(v: str | None) -> str | None:
    if v and not croniter.is_valid(v):
        raise ValueError("sync_schedule must be a valid cron expression")
    return v


class CreateIntegrationRequest(BaseModel):
    vendor: Vendor
    name: str = Field(min_length=1, max_length=128)
    config: dict = {}
    is_enabled: bool = True
    sync_schedule: str | None = Field(None, max_length=64)

    _cron = field_validator("sync_schedule")(_check_cron)


class UpdateIntegrationRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    is_enabled: bool | None = None
    config: dict | None = None
    sync_schedule: str | None = Field(None, max_length=64)

    _cron = field_validator("sync_schedule")(_check_cron)
