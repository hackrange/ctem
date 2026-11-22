"""Collector auth, run bookkeeping, and per-kind upsert dispatch."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.collector.schemas import CrowdStrikeBatch, LdapBatch, Rapid7Batch, SplunkBatch
from api.models.collector import CollectorProfile, CollectorToken
from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor

log = logging.getLogger("open-ctem.collector")

TOKEN_PREFIX = "occ_"  # nosec B105 - public prefix, not a secret
_TOKEN_RE = re.compile(r"^occ_[0-9a-f]{64}$")
_RATE_PER_MIN = 600

# Which integration vendors a collector is allowed to feed, and the push kind for each
KIND_FOR_VENDOR = {Vendor.ldap: "ldap", Vendor.rapid7_insightvm: "rapid7_console", Vendor.crowdstrike: "crowdstrike",
                   Vendor.splunk: "splunk"}


VENDOR_FOR_KIND = {k: v for v, k in KIND_FOR_VENDOR.items()}
_KIND_LABEL = {"ldap": "LDAP", "rapid7_console": "Rapid7 InsightVM console", "crowdstrike": "CrowdStrike Falcon",
               "splunk": "Splunk"}


def hash_secret(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _deny() -> HTTPException:
    # Same answer for unknown, revoked, and wrong-IP so nobody can probe which one it was
    return HTTPException(401, detail="Invalid collector token")


async def authenticate(request: Request, db: AsyncSession) -> CollectorToken:
    from api.auth.middleware import _ip_allowed
    from api.core.security import _client_ip

    auth = request.headers.get("authorization", "")
    raw = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not _TOKEN_RE.match(raw):
        raise _deny()
    digest = hash_secret(raw)
    tok = (await db.execute(
        select(CollectorToken).where(CollectorToken.token_hash == digest, CollectorToken.is_active == True)  # noqa: E712
    )).scalar_one_or_none()
    if tok is None or not hmac.compare_digest(tok.token_hash, digest):
        raise _deny()
    ip = _client_ip(request)
    if not _ip_allowed(ip, tok.allowed_ips or []):
        log.warning("collector %s used from unlisted ip %s", tok.id, ip)
        raise _deny()
    await _rate_limit(tok.id)
    tok.last_seen = datetime.now(timezone.utc)
    tok.last_seen_ip = ip
    return tok


async def _rate_limit(token_id: str) -> None:
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    try:
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        key = f"rl:collector:{token_id}"
        n = await r.incr(key)
        if n == 1:
            await r.expire(key, 60)
        await r.aclose()
    except Exception:
        log.warning("collector rate limit skipped (Redis down?)")
        return
    if n > _RATE_PER_MIN:
        raise HTTPException(429, detail="Too many requests")


async def profile_of(tok: CollectorToken, db: AsyncSession) -> CollectorProfile:
    prof = (await db.execute(select(CollectorProfile).where(CollectorProfile.id == tok.profile_id))).scalar_one_or_none()
    if prof is None:
        raise _deny()
    return prof


def owned_ids(prof: CollectorProfile) -> dict[str, str]:
    """kind -> integration_id for every enabled module of this profile."""
    return {k: m["integration_id"] for k, m in (prof.modules or {}).items()
            if m.get("enabled", True) and m.get("integration_id")}


async def scoped_integration(tok: CollectorToken, integration_id: str, kind: str, db: AsyncSession) -> IntegrationConfig:
    """Object-level check: the shipper's profile must own this integration and the kind must match its vendor."""
    prof = await profile_of(tok, db)
    if owned_ids(prof).get(kind) != integration_id:
        raise HTTPException(404)
    cfg = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.id == integration_id, IntegrationConfig.is_enabled == True)  # noqa: E712
    )).scalar_one_or_none()
    if cfg is None or KIND_FOR_VENDOR.get(cfg.vendor) != kind:
        raise HTTPException(404)
    return cfg


async def track_run(db: AsyncSession, cfg: IntegrationConfig, run_id: str, count: int, final: bool,
                    warnings: list[str] | None = None) -> SyncJob:
    now = datetime.now(timezone.utc)
    job = (await db.execute(select(SyncJob).where(SyncJob.id == run_id))).scalar_one_or_none()
    if job is None:
        # A fresh run means any earlier unfinished one is dead
        stale = await db.execute(select(SyncJob).where(
            SyncJob.integration_id == str(cfg.id), SyncJob.status == SyncStatus.running))
        for s in stale.scalars():
            s.status, s.finished_at, s.error_message = SyncStatus.failed, now, "Collector run did not finish"
        job = SyncJob(id=run_id, integration_id=str(cfg.id), vendor=cfg.vendor.value,
                      status=SyncStatus.running, started_at=now, records_imported=0)
        db.add(job)
    elif job.integration_id != str(cfg.id) or job.status != SyncStatus.running:
        raise HTTPException(409, detail="Run is not open")
    job.records_imported = (job.records_imported or 0) + count
    for w in warnings or []:   # kept on the run; a successful run with warnings shows them on the card
        if w not in (job.error_message or ""):
            job.error_message = "; ".join(filter(None, [job.error_message, f"warning: {w}"]))[:1000]
    if final:
        job.status, job.finished_at = SyncStatus.success, now
        cfg.last_sync_at, cfg.last_sync_status, cfg.last_sync_error = now, SyncStatus.success, job.error_message
        if KIND_FOR_VENDOR.get(cfg.vendor) == "crowdstrike" and job.started_at:
            await _crowdstrike_finished(db, cfg, run_id, job.started_at)
        if KIND_FOR_VENDOR.get(cfg.vendor) == "rapid7_console" and job.started_at:
            from api.core.software_ingest import prune_run
            if await prune_run(db, "rapid7_insightvm", job.started_at) is not None:   # a software pass mirrors the console
                from api.collector.software_resend import restore
                await restore(db, str(cfg.id))   # and ends a "send software sooner" request
    return job


async def mark_full_spotlight(db: AsyncSession, cfg: IntegrationConfig, run_id: str) -> None:
    """This run carries a full Spotlight pass: at its end, what Falcon no longer lists is closed."""
    from api.models.settings import AppSetting
    key = f"spotlight_full_run.{cfg.id}"
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=key, value=run_id))
    else:
        row.value = run_id


async def _crowdstrike_finished(db: AsyncSession, cfg: IntegrationConfig, run_id: str, started) -> None:
    from api.core.software_ingest import prune_run
    from api.models.settings import AppSetting
    await prune_run(db, "crowdstrike_discover", started)   # a Discover pass mirrors Falcon's installed apps
    row = (await db.execute(select(AppSetting).where(AppSetting.key == f"spotlight_full_run.{cfg.id}"))).scalar_one_or_none()
    if row is not None and row.value == run_id:
        from api.integrations.crowdstrike_spotlight import close_unseen
        await close_unseen(db, started)
        await db.delete(row)


async def apply_batch(db: AsyncSession, batch: LdapBatch | Rapid7Batch | CrowdStrikeBatch | SplunkBatch) -> int:
    if isinstance(batch, LdapBatch):
        from api.integrations.ldap_ingest import upsert_directory
        return await upsert_directory(
            [u.model_dump() for u in batch.users],
            [c.model_dump() for c in batch.computers],
            db, commit=False,
        )
    if isinstance(batch, SplunkBatch):
        from api.integrations.splunk import SplunkConnector
        sp = SplunkConnector({})
        if batch.events:
            await sp._cache_threats(list(batch.events), db)
        if batch.indexes is not None:
            await sp._refresh_spl_catalog(db, [i.model_dump() for i in batch.indexes])
        return len(batch.events) + len(batch.indexes or [])
    if isinstance(batch, CrowdStrikeBatch):
        from api.integrations.crowdstrike import CrowdStrikeConnector
        cs = CrowdStrikeConnector({})
        if batch.edr_policies:   # sent ahead of the hosts that point at them
            from api.core.edr_policies import upsert as upsert_policies
            await upsert_policies(db, "crowdstrike", [p.model_dump(exclude_none=True) for p in batch.edr_policies])
        n = await cs._upsert([d.model_dump(exclude_none=True) for d in batch.devices], [], db)
        if batch.spotlight:
            from api.integrations.crowdstrike_spotlight import upsert as spotlight
            n += await spotlight(db, [c.model_dump(exclude_none=True) for c in batch.spotlight_cves],
                                 [v.model_dump(exclude_none=True) for v in batch.spotlight])
        if batch.software:
            from api.core.software_ingest import upsert as software
            n += await software(db, [x.model_dump(exclude_none=True) for x in batch.software], "crowdstrike_discover")
        if batch.intel or batch.stream_events or batch.hunt:
            from api.core import hunt_ingest as hi
            n += await hi.intel(db, [x.model_dump(exclude_none=True) for x in batch.intel])
            n += await hi.stream_events(db, [x.model_dump(exclude_none=True) for x in batch.stream_events])
            n += await hi.stacks(db, [x.model_dump(exclude_none=True) for x in batch.hunt])
        if batch.detections:
            await cs._cache_threats([d.model_dump(exclude_none=True) for d in batch.detections], db)
        return n + len(batch.detections)
    from api.integrations.rapid7_insightvm import InsightVMConnector
    conn = InsightVMConnector({})
    n = await conn._console_upsert_assets([a.model_dump(exclude_none=True) for a in batch.assets], db)
    n += await conn._console_upsert_vulns([v.model_dump(exclude_none=True) for v in batch.vulnerabilities], db)
    if batch.software:
        from api.core.software_ingest import upsert
        n += await upsert(db, [s.model_dump(exclude_none=True) for s in batch.software], "rapid7_insightvm")
    return n


async def record_error(db: AsyncSession, tok: CollectorToken, prof: CollectorProfile, errors: dict[str, str]) -> None:
    now = datetime.now(timezone.utc)
    tok.last_error = "; ".join(f"{k}: {v}" for k, v in errors.items())[:500] or None
    owned = owned_ids(prof)
    for kind, msg in errors.items():
        iid = owned.get(kind)
        if not iid:
            continue  # can't flag an integration you don't own
        cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == iid))).scalar_one_or_none()
        if cfg is None:
            continue
        cfg.last_sync_at, cfg.last_sync_status, cfg.last_sync_error = now, SyncStatus.failed, f"shipper: {msg}"[:500]
        db.add(SyncJob(integration_id=iid, vendor=cfg.vendor.value, status=SyncStatus.failed,
                       started_at=now, finished_at=now, records_imported=0, error_message=f"shipper: {msg}"[:1000]))


async def ensure_integrations(db: AsyncSession, prof: CollectorProfile) -> None:
    """Every module gets a collector-mode integration so its data has a home and a status chip."""
    mods = dict(prof.modules or {})
    for kind, m in mods.items():
        if m.get("integration_id"):
            continue
        cfg = IntegrationConfig(vendor=VENDOR_FOR_KIND[kind], name=f"{_KIND_LABEL[kind]} ({prof.name})"[:128],
                                is_enabled=True, config={"mode": "collector", "collector": prof.name})
        db.add(cfg)
        await db.flush()
        mods[kind] = {**m, "integration_id": str(cfg.id)}
    prof.modules = mods  # reassign so the encrypted column notices


def enrollment_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=24)
