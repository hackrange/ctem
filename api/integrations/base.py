"""Abstract base for all integration connectors."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from croniter import croniter
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor

log = logging.getLogger("open-ctem.integrations")


class BaseConnector(ABC):
    """Every integration inherits from this. Keeps the interface uniform."""

    vendor: Vendor  # set by subclass

    def __init__(self, config: dict[str, Any]) -> None:
        # Blank form fields arrive as "", which should mean "use the default"
        self.config = {k: v for k, v in (config or {}).items() if v not in ("", None)}
        self.integration_id: str | None = None  # set by sync_by_id; enables incremental sync state

    @abstractmethod
    async def test_connection(self) -> bool:
        """Return True if credentials are valid and the API is reachable."""
        ...

    @abstractmethod
    async def sync(self, db: AsyncSession) -> int:
        """
        Pull data, upsert into DB. Return number of records imported.
        Must be idempotent -- safe to run multiple times.
        """
        ...

    @property
    def name(self) -> str:
        return self.vendor.value


# ── Registry ──────────────────────────────────────────────────────────────────

_REGISTRY: dict[str, type[BaseConnector]] = {}


def register(vendor: Vendor):
    """Decorator to register a connector class."""
    def _dec(cls: type[BaseConnector]):
        _REGISTRY[vendor.value] = cls
        cls.vendor = vendor
        return cls
    return _dec


def get_connector(vendor_slug: str, config: dict) -> BaseConnector:
    cls = _REGISTRY.get(vendor_slug)
    if cls is None:
        raise ValueError(f"No connector registered for vendor: {vendor_slug!r}")
    return cls(config)


# ── Incremental sync bookmarks ───────────────────────────────────────────────

async def load_sync_state(db: AsyncSession, integration_id: str | None) -> dict:
    import json

    from api.models.settings import AppSetting
    if not integration_id:
        return {}
    row = (await db.execute(select(AppSetting).where(AppSetting.key == f"sync_state.{integration_id}"))).scalar_one_or_none()
    try:
        return json.loads(row.value) if row and row.value else {}
    except ValueError:
        return {}


async def save_sync_state(db: AsyncSession, integration_id: str | None, state: dict) -> None:
    import json

    from api.models.settings import AppSetting
    if not integration_id:
        return
    key = f"sync_state.{integration_id}"
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=key, value=json.dumps(state), is_sensitive=False))
    else:
        row.value = json.dumps(state)
    await db.commit()


# ── Sync orchestration ────────────────────────────────────────────────────────

async def sync_by_id(db: AsyncSession, integration_id: str) -> bool:
    """Run one integration's sync. Returns True when it succeeded."""
    # Two syncs of the same integration at once (a click on Sync Now during a scheduled run)
    # both insert the same rows; let the second one bow out
    lock = await _sync_lock(str(integration_id))
    if lock is False:
        log.info("sync of %s already running; skipping this one", integration_id)
        return False
    try:
        return await _sync_by_id(db, integration_id)
    finally:
        if lock:
            await _sync_unlock(*lock)


async def _sync_lock(integration_id: str):
    """(redis, key, token) when we hold the lock, False when someone else does, None if Redis is down."""
    import secrets

    import redis.asyncio as aioredis

    from api.core.config import get_settings
    try:
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        key, token = f"sync_lock:{integration_id}", secrets.token_hex(8)
        if await r.set(key, token, nx=True, ex=3 * 3600):
            return r, key, token
        await r.aclose()
        return False
    except Exception:
        log.warning("sync lock skipped (Redis down?)")
        return None


async def _sync_unlock(r, key: str, token: str) -> None:
    try:
        if await r.get(key) == token:  # only drop our own lock
            await r.delete(key)
        await r.aclose()
    except Exception:
        log.warning("could not release sync lock %s", key)


async def _sync_by_id(db: AsyncSession, integration_id: str) -> bool:
    ok = False
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == str(integration_id),
            IntegrationConfig.is_enabled == True,  # noqa: E712
        )
    )
    cfg = result.scalar_one_or_none()
    if cfg is None or is_collector_fed(cfg):
        return False  # collector-fed integrations get pushed to, never pulled

    job = SyncJob(
        integration_id=str(cfg.id),
        vendor=cfg.vendor.value,
        status=SyncStatus.running,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.commit()
    job_id, cfg_id, vendor, config = job.id, str(cfg.id), cfg.vendor.value, cfg.config or {}

    # The outcome is written by id, not through the ORM objects above: a connector may
    # expunge the session between pages (InsightVM does), which detaches them, and then
    # changes to them are silently never saved. That left jobs "running" forever.
    job_vals: dict = {"status": SyncStatus.failed}
    cfg_vals: dict = {"last_sync_status": SyncStatus.failed}
    try:
        from api.core import tag_roles
        await tag_roles.ensure(db)   # connectors that export owners or environments read the tag mapping
        connector = get_connector(vendor, config)
        connector.integration_id = cfg_id
        count = await connector.sync(db)
        job_vals = {"status": SyncStatus.success, "records_imported": count}
        cfg_vals = {"last_sync_status": SyncStatus.success, "last_sync_error": None}
        ok = True
    except Exception as e:
        await db.rollback()
        job_vals = {"status": SyncStatus.failed, "error_message": str(e)[:1000]}
        cfg_vals = {"last_sync_status": SyncStatus.failed, "last_sync_error": str(e)[:500]}
    finally:
        done = datetime.now(timezone.utc)
        await db.execute(update(SyncJob).where(SyncJob.id == job_id).values(finished_at=done, **job_vals))
        await db.execute(update(IntegrationConfig).where(IntegrationConfig.id == cfg_id)
                         .values(last_sync_at=done, **cfg_vals))
        await db.commit()
    return ok


async def run_due_syncs(db: AsyncSession) -> None:
    """Check all enabled integrations and kick off any that are past their schedule."""
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.is_enabled == True,  # noqa: E712
            IntegrationConfig.sync_schedule.isnot(None),
        )
    )
    for cfg in result.scalars():
        if not is_collector_fed(cfg) and _is_due(cfg):
            from api.core.tasks import sync_integration
            sync_integration.delay(str(cfg.id))


def is_collector_fed(cfg: IntegrationConfig) -> bool:
    return (cfg.config or {}).get("mode") == "collector"


def _is_due(cfg: IntegrationConfig) -> bool:
    """True if the integration has never run or its cron schedule is overdue."""
    if cfg.last_sync_at is None:
        return True
    try:
        cron = croniter(cfg.sync_schedule, cfg.last_sync_at)
        return datetime.now(timezone.utc) >= cron.get_next(datetime)
    except Exception:
        return False
