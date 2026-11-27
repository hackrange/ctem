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

from api.auth.rbac import require_admin
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
    """Per-vendor checks before a config is stored. Bedrock and the clouds have no URL at all: the region
    (or cloud name) picks AWS's, Azure's or Oracle's own endpoint."""
    if vendor in (Vendor.aws, Vendor.azure, Vendor.oci):
        from api.cloud import aws, azure, oci
        if config.get("base_url"):
            raise HTTPException(400, "Cloud integrations don't take a base URL")
        checker = {Vendor.aws: aws.check, Vendor.azure: azure.check, Vendor.oci: oci.check}[vendor]
        if any(v == "__REDACTED__" for v in config.values()):
            return   # an edit that keeps a saved secret; checked again when it syncs
        try:
            checker(config)
        except ValueError as exc:
            raise HTTPException(400, str(exc).capitalize()) from exc
        return
    if vendor == Vendor.okta:
        from api.integrations.okta import org_host
        try:
            org_host(config)
            if not str(config.get("base_url") or "").lower().startswith("https://"):
                raise ValueError("the Okta domain must start with https://")
            if config.get("factor_budget") not in (None, "") and not 0 <= int(config["factor_budget"]) <= 20000:
                raise ValueError("MFA lookups per sync must be from 0 to 20000")
            if config.get("app_budget") not in (None, "") and not 0 <= int(config["app_budget"]) <= 20000:
                raise ValueError("App list lookups per sync must be from 0 to 20000")
            if config.get("device_interval_days") not in (None, "") and not 0 <= int(config["device_interval_days"]) <= 90:
                raise ValueError("The device pull interval must be from 0 to 90 days")
        except ValueError as exc:
            raise HTTPException(400, str(exc)[:200]) from exc
        return
    if vendor in (Vendor.persona, Vendor.twilio):
        from api.integrations.idv_config import check
        try:
            check(vendor.value, config)
        except ValueError as exc:
            raise HTTPException(400, str(exc)[:200]) from exc
        return
    if vendor == Vendor.github_code_review:
        from api.integrations.gcr_client import GcrError, base_url
        from api.integrations.github_code_review import tag_map
        try:
            if config.get("base_url"):
                base_url(config)
            tag_map(config.get("tag_map"))
        except (GcrError, ValueError) as exc:
            raise HTTPException(400, f"Tag map or URL: {exc}") from exc
        return
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
_VENDOR_LABELS = {"email": "Email (SMTP or Microsoft 365)", "github_code_review": "GitHub Code Review (SAST and DAST)", "aws": "AWS (cloud exposure)", "azure": "Azure (cloud exposure)", "oci": "Oracle Cloud OCI (cloud exposure)",
                  "okta": "Okta (identity provider, read only)", "persona": "Persona (identity verification)",
                  "twilio": "Twilio (SMS for identity verification)",
                  "tanium": "Tanium (endpoints, patches, vulnerabilities; read only)"}


@router.get("")
async def list_integrations(
    u: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).order_by(IntegrationConfig.vendor))
    owned = await _shipper_owned(db)
    return {"integrations": [{**_summary(i), "shipper_managed": str(i.id) in owned} for i in result.scalars()],
            "can_truncate": "admin" in u.role_names}


async def _shipper_owned(db) -> set[str]:
    """Integration ids a shipper still owns (any of its sources, enabled or not)."""
    from api.models.collector import CollectorProfile
    out = set()
    for prof in (await db.execute(select(CollectorProfile))).scalars():
        out.update(str(m["integration_id"]) for m in (prof.modules or {}).values() if m.get("integration_id"))
    return out


@router.get("/vendors")
async def list_vendors(
    _: User = Depends(require_admin),
):
    """All vendor slugs supported by this instance -- for the add-integration modal."""
    return {
        "vendors": [
            {"slug": v.value, "label": _VENDOR_LABELS.get(v.value, v.value.replace("_", " ").title())}
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
    if body.vendor == Vendor.splunk and not body.config.get("ssl_mode"):
        from api.integrations.splunk import new_ssl_mode
        body.config["ssl_mode"] = new_ssl_mode(body.config)   # new ones verify
    if body.vendor == Vendor.ldap:
        from api.integrations.ldap import new_tls_settings
        body.config.update(new_tls_settings(body.config))   # new ones bind over LDAPS or StartTLS, never in the clear
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
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == str(integration_id)))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(404)
    return _summary(cfg)


async def _not_shipper_run(db, cfg: IntegrationConfig) -> None:
    """While a shipper owns an integration it is changed and removed on the Shippers tab only (its connection,
    credentials and schedule live on the shipper), so the integration routes refuse to touch it. Once no shipper
    owns it (the shipper or that source was removed), it can be cleaned up here."""
    if str(cfg.id) in await _shipper_owned(db):
        raise HTTPException(409, "Managed by a shipper: change or remove it under Settings > Shippers")


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
    await _not_shipper_run(db, cfg)
    if body.name is not None:
        cfg.name = body.name
    if body.is_enabled is not None:
        cfg.is_enabled = body.is_enabled
    if body.config is not None:
        if body.config.get("base_url"):
            _validate_base_url(body.config["base_url"])
        # Merge: keep existing secret values when the client sends back the redacted sentinel
        existing = dict(cfg.config or {})
        # A saved secret is only reused for the same endpoint, so it can't be pointed at another server. Blank
        # and missing are the same (an empty form field).
        norm = lambda v: "" if v in (None, False, "false", "0", 0) else str(v).strip().rstrip("/").lower()  # noqa: E731
        if "start_tls" in existing and "start_tls" not in body.config:   # set at creation, not on the form: an
            body.config["start_tls"] = existing["start_tls"]             # edit must never drop StartTLS
        # Every setting that says where requests (and so the saved secret) go, by name, whether sent, changed or
        # left out: leaving base_url out while setting a fallback "domain" moves the endpoint just the same
        moved = any(norm(body.config.get(k)) != norm(existing.get(k))
                    for k in {*body.config, *existing} if _ENDPOINT_RE.search(k) or _TRANSPORT_RE.search(k))
        if moved and "__REDACTED__" in body.config.values():
            raise HTTPException(400, "Re-enter credentials when changing the endpoint")
        merged = {
            k: existing[k] if v == "__REDACTED__" else v
            for k, v in body.config.items()
            if v not in ("", None) and (v != "__REDACTED__" or existing.get(k) not in ("", None))   # never store the sentinel
        }
        _check_vendor_config(cfg.vendor, merged)
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
    await _not_shipper_run(db, cfg)
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
    _: User = Depends(require_admin),
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
    from api.auth.account_seal import collector_intact
    toks = (await db.execute(select(CollectorToken).where(CollectorToken.is_active == True))).scalars()  # noqa: E712
    for t in (t for t in toks if collector_intact(t)):
        seen = t.last_seen
        if seen is not None and seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        if str(cfg.id) in (t.integration_ids or []) and seen and seen >= cutoff:
            return True
    return False


# extra_headers can carry an Authorization header (the AI connector merges it into requests), so it's a secret too
_SECRET_RE = re.compile(r"(secret|passw|pass$|passphrase|token|api_?key|private_?key|credential|headers)", re.I)
# base_url, hec_url, console_host, vanity_domain, domain, instance_url, tenant_id...; not internal_domains (a list)
_ENDPOINT_RE = re.compile(r"(^|_)(url|host|server|endpoint|domain|instance|tenant_id)$", re.I)
# ...and how they travel: a saved password must not be reused once it would go in the clear or to another port
_TRANSPORT_RE = re.compile(r"^(port|ssl_mode|no_ssl|use_ssl|use_tls|start_tls|tls_skip_verify|allow_http)$")


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
        "last_sync_note": (cfg.last_sync_error or "")[:500] or None,   # a failure, a shipper warning or a truncate
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
