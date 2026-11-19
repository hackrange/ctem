"""Abstract base for all integration connectors."""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor


class BaseConnector(ABC):
    """Every integration inherits from this. Keeps the interface uniform."""

    vendor: Vendor  # set by subclass

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

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


# ── Sync orchestration ────────────────────────────────────────────────────────

async def sync_by_id(db: AsyncSession, integration_id: str) -> None:
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == uuid.UUID(integration_id),
            IntegrationConfig.is_enabled == True,  # noqa: E712
        )
    )
    cfg = result.scalar_one_or_none()
    if cfg is None:
        return

    job = SyncJob(
        integration_id=str(cfg.id),
        vendor=cfg.vendor.value,
        status=SyncStatus.running,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.commit()

    try:
        connector = get_connector(cfg.vendor.value, cfg.config or {})
        count = await connector.sync(db)
        job.status = SyncStatus.success
        job.records_imported = count
        cfg.last_sync_status = SyncStatus.success
    except Exception as e:
        job.status = SyncStatus.failed
        job.error_message = str(e)[:1000]
        cfg.last_sync_status = SyncStatus.failed
        cfg.last_sync_error = str(e)[:500]
    finally:
        job.finished_at = datetime.now(timezone.utc)
        cfg.last_sync_at = job.finished_at
        await db.commit()


async def run_due_syncs(db: AsyncSession) -> None:
    """Check all enabled integrations and kick off any that are past their schedule."""
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.is_enabled == True,  # noqa: E712
            IntegrationConfig.sync_schedule.isnot(None),
        )
    )
    for cfg in result.scalars():
        if _is_due(cfg):
            from api.core.tasks import sync_integration
            sync_integration.delay(str(cfg.id))


def _is_due(cfg: IntegrationConfig) -> bool:
    """True if the integration has never run or its cron schedule is overdue."""
    if cfg.last_sync_at is None:
        return True
    try:
        cron = croniter(cfg.sync_schedule, cfg.last_sync_at)
        return datetime.now(timezone.utc) >= cron.get_next(datetime)
    except Exception:
        return False
