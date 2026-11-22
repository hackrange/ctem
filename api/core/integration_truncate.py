"""Remove the data one integration's source reported, so its next sync starts clean.

Data is tagged by source (the vendor), not by integration, so integrations of the same vendor share it: truncating
one removes the other's too, and the warning names them. Assets no other source reports are deleted; the rest
only lose this source's findings, software, tag links and fields. Decisions people made are kept: software titles
and their review, tags (access rules hang off them), and vulnerabilities that carry an exception."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import delete, exists, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

NOT_DATA = frozenset({"ai", "anthropic", "openai", "custom_ai", "bedrock", "fairtprm", "servicenow", "email"})
BATCH = 20000
KEY = "truncating:{}"   # Redis: set while a truncate runs (ingest and syncs of that source wait)
_EDR_FIELDS = {"edr_vendor": None, "edr_active": False, "edr_last_seen": None, "edr_device_id": None,
               "edr_contained": None, "edr_hidden": None, "firewall_enabled": None, "usb_storage_blocked": None}
_AD_FIELDS = ("ad_dn", "ad_last_logon", "ad_ou_keys")


def truncatable(vendor: str) -> bool:
    return vendor not in NOT_DATA


def _src(slug: str):
    from api.models.device import Device
    return Device.sources.like(f"%,{slug},%")


def _only_src(slug: str):
    """Assets this source alone reports."""
    from api.models.device import Device
    return or_(Device.sources == f",{slug},", (Device.source == slug) & or_(Device.sources.is_(None), Device.sources == ","))


async def preview(db: AsyncSession, cfg) -> dict:
    """What a truncate would remove, and which other integrations share the data."""
    from api.models.device import Device
    from api.models.integration import IntegrationConfig
    from api.models.software import SoftwareInstall
    from api.models.vuln import Finding
    slug = cfg.vendor.value
    n = lambda stmt: db.execute(stmt)  # noqa: E731
    shared = [c.name for c in (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.vendor == cfg.vendor, IntegrationConfig.id != cfg.id))).scalars()]
    return {
        "truncatable": truncatable(slug), "source": slug, "shared_with": sorted(shared),
        "findings": (await n(select(func.count()).select_from(Finding).where(Finding.source == slug))).scalar_one(),
        "assets_deleted": (await n(select(func.count()).select_from(Device).where(_only_src(slug)))).scalar_one(),
        "assets_kept": (await n(select(func.count()).select_from(Device).where(_src(slug), ~_only_src(slug)))).scalar_one(),
        "software_installs": (await n(select(func.count()).select_from(SoftwareInstall).where(
            SoftwareInstall.source == slug))).scalar_one(),
    }


async def _batched(db: AsyncSession, model, *where) -> int:
    total = 0
    while True:
        ids = select(model.id).where(*where).limit(BATCH).scalar_subquery()
        r = await db.execute(delete(model).where(model.id.in_(ids)).execution_options(synchronize_session=False))
        await db.commit()
        total += r.rowcount or 0
        if not r.rowcount:
            return total


async def run(db: AsyncSession, cfg, actor: str) -> dict:
    """Remove the source's data in batches; returns what was removed. The caller holds the locks."""
    from api.models.cloud import CloudAsset
    from api.models.device import Device, DeviceTag
    from api.models.integration import IntegrationConfig, SyncStatus
    from api.models.settings import AppSetting, AuditLog
    from api.models.software import SoftwareInstall
    from api.models.tag import Tag
    from api.models.vuln import Finding, Vulnerability, VulnException
    slug, vendor, cfg_id, cfg_name = cfg.vendor.value, cfg.vendor, str(cfg.id), cfg.name   # before any commit
    out = {"findings": await _batched(db, Finding, Finding.source == slug),
           "software_installs": await _batched(db, SoftwareInstall, SoftwareInstall.source == slug)}
    out["vulnerabilities"] = await _batched(db, Vulnerability, Vulnerability.source == slug,
                                            ~exists().where(Finding.vuln_id == Vulnerability.id),
                                            ~exists().where(VulnException.vuln_id == Vulnerability.id))
    out["assets_deleted"] = await _batched(db, Device, _only_src(slug))
    r = await db.execute(delete(DeviceTag).where(DeviceTag.tag_id.in_(select(Tag.id).where(Tag.source == slug)))
                         .execution_options(synchronize_session=False))
    out["tag_links"] = r.rowcount or 0
    clear = {"sources": func.replace(Device.sources, f",{slug},", ",")}
    r = await db.execute(update(Device).where(_src(slug)).values(**clear).execution_options(synchronize_session=False))
    out["assets_kept"] = r.rowcount or 0
    await db.execute(update(Device).where(Device.edr_vendor == slug).values(**_EDR_FIELDS)
                     .execution_options(synchronize_session=False))
    if slug == "ldap":
        await db.execute(update(Device).where(Device.ad_dn.is_not(None)).values(
            **{f: None for f in _AD_FIELDS}, ad_joined=False).execution_options(synchronize_session=False))
    from api.models.identity import IdentityThreat, PostureFinding
    for model in (IdentityThreat, PostureFinding):
        await db.execute(delete(model).where(model.source == slug).execution_options(synchronize_session=False))
    same = [str(i) for (i,) in (await db.execute(select(IntegrationConfig.id).where(IntegrationConfig.vendor == vendor))).all()]
    await db.execute(delete(CloudAsset).where(CloudAsset.integration_id.in_(same)).execution_options(synchronize_session=False))
    out["alerts"] = await _alerts(db, slug)
    # Next sync is a full one, and the cards say what happened
    await db.execute(delete(AppSetting).where(AppSetting.key.in_([f"sync_state.{i}" for i in same])))
    note = f"Data truncated by {actor} on {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC; the next sync brings it back"
    await db.execute(update(IntegrationConfig).where(IntegrationConfig.id.in_(same)).values(
        last_sync_at=None, last_sync_status=SyncStatus.pending, last_sync_error=note[:500]))
    db.add(AuditLog(actor_username=actor, action="integration.truncate", resource_type="integration",
                    resource_id=cfg_id, detail=f"{cfg_name} ({slug}): " + json.dumps(out)[:240]))
    await db.commit()
    return out


async def _alerts(db: AsyncSession, slug: str) -> int:
    """Cached EDR/SIEM alerts from this source (stored as settings rows)."""
    from api.models.settings import AppSetting
    gone = []
    for row in (await db.execute(select(AppSetting).where(AppSetting.key.like("threat\\_%", escape="\\")))).scalars():
        try:
            if json.loads(row.value or "{}").get("source") == slug:
                gone.append(row.id)
        except (ValueError, AttributeError):
            continue
    for i in range(0, len(gone), 1000):
        await db.execute(delete(AppSetting).where(AppSetting.id.in_(gone[i:i + 1000])))
    await db.commit()
    return len(gone)


async def start(cfg_id: str, actor: str) -> dict:
    """Run a truncate under the locks: every integration of the vendor is held (syncs skip, shipper uploads wait)."""
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    from api.core.db import get_session
    from api.models.integration import IntegrationConfig
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    held: list[str] = []
    try:
        async for db in get_session():
            cfg = await db.get(IntegrationConfig, cfg_id)
            if cfg is None or not truncatable(cfg.vendor.value):
                return {"error": "not found"}
            same = [str(i) for (i,) in (await db.execute(select(IntegrationConfig.id).where(
                IntegrationConfig.vendor == cfg.vendor))).all()]
            for i in same:
                if not await r.set(f"sync_lock:{i}", "truncate", nx=True, ex=6 * 3600):
                    return {"error": "a sync of this source is running; try again when it finishes"}
                held.append(i)
            for i in same:
                await r.set(KEY.format(i), json.dumps({"by": actor, "at": datetime.now(timezone.utc).isoformat()}),
                            ex=6 * 3600)
            try:
                return await run(db, cfg, actor)
            except Exception:
                log.exception("truncate of %s failed", cfg_id)
                await db.rollback()
                return {"error": "failed"}
    finally:
        for i in held:
            if await r.get(f"sync_lock:{i}") == "truncate":
                await r.delete(f"sync_lock:{i}")
            await r.delete(KEY.format(i))
        await r.aclose()
    return {"error": "no database"}


async def running(integration_id: str) -> bool:
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    try:
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            return bool(await r.exists(KEY.format(integration_id)))
        finally:
            await r.aclose()
    except Exception:
        log.warning("truncate status unknown (Redis down?)")
        return False
