"""Endpoints the on-prem shipper calls: enroll once, check in for config, upload sealed secrets, push batches."""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Annotated, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.collector import ingest, service
from api.collector.profile import key_fingerprint
from api.collector.schemas import (
    CheckinRequest, CrowdStrikeBatch, EnrollRequest, LdapBatch, LoginCheckRequest, LoginEnrollRequest, Rapid7Batch,
    NetProbeBatch, SecretsUpload, SplunkBatch,
)
from api.core.db import get_session
from api.models.collector import CollectorEnrollment, CollectorProfile, CollectorToken

log = logging.getLogger("open-ctem.collector")
router = APIRouter(prefix="/api/v1/collector", tags=["collector"])

_MAX_BODY = 8 * 1024 * 1024


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")
_Batch = TypeAdapter(Annotated[Union[LdapBatch, Rapid7Batch, CrowdStrikeBatch, SplunkBatch, NetProbeBatch], Field(discriminator="kind")])


async def _json_body(request: Request, model):
    # Parse by hand so unauthenticated callers never get schema hints back
    if int(request.headers.get("content-length") or 0) > _MAX_BODY:
        raise HTTPException(413, detail="Payload too large")
    raw = await request.body()
    if len(raw) > _MAX_BODY:
        raise HTTPException(413, detail="Payload too large")
    try:
        data = json.loads(raw)
        return model.validate_python(data) if isinstance(model, TypeAdapter) else model.model_validate(data)
    except ValidationError as exc:
        # Locations and error types only; pydantic's message would echo input, passwords included
        log.info("collector payload rejected: %s", [(e["loc"], e["type"]) for e in exc.errors(include_input=False)][:10])
        raise HTTPException(400, detail="Invalid payload") from None
    except ValueError:
        log.info("collector payload rejected: not JSON")
        raise HTTPException(400, detail="Invalid payload") from None


def _fingerprint(pem: str) -> str:
    try:
        return key_fingerprint(pem)
    except (ValueError, TypeError):
        raise HTTPException(400, detail="Invalid payload") from None


async def _mint(db: AsyncSession, prof: CollectorProfile, pem: str, host: str, version: str, ip: str, pinned: list[str]) -> dict:
    fp = _fingerprint(pem)
    now = datetime.now(timezone.utc)
    # One box per profile; re-installing replaces the old box's credential and key
    old = await db.execute(select(CollectorToken).where(
        CollectorToken.profile_id == prof.id, CollectorToken.is_active == True))  # noqa: E712
    from api.auth.account_seal import seal_collector
    for t in old.scalars():
        t.is_active = False
        seal_collector(t)
    await ingest.ensure_integrations(db, prof)
    plain = ingest.TOKEN_PREFIX + secrets.token_hex(32)
    tok = CollectorToken(
        profile_id=prof.id, token_hash=ingest.hash_secret(plain), public_key=pem.strip(), key_fp=fp,
        allowed_ips=pinned or [ip], is_active=True, collector_host=host, agent_version=version,
        last_seen=now, last_seen_ip=ip, approved={},
    )
    db.add(tok)
    await db.flush()
    seal_collector(tok)
    await db.commit()
    log.info("shipper for profile %s enrolled from %s key %s", prof.name, ip, fp[:16])
    return {"token": plain, "collector_id": str(tok.id), "key_fp": fp,
            "config": service.agent_config(prof, [], tok)}


@router.post("/enroll")
async def enroll(request: Request, db: AsyncSession = Depends(get_session)):
    from api.auth.middleware import _ip_allowed
    from api.core.security import _client_ip

    body: EnrollRequest = await _json_body(request, EnrollRequest)
    digest = ingest.hash_secret(body.code)
    enr = (await db.execute(select(CollectorEnrollment).where(
        CollectorEnrollment.code_hash == digest, CollectorEnrollment.used_at.is_(None)))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    exp = enr.expires_at if enr else None
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)  # sqlite drops tz
    if enr is None or exp is None or exp < now:
        raise HTTPException(401, detail="Invalid enrollment code")
    ip = _client_ip(request)
    pinned = list(enr.allowed_ips or [])
    if pinned and not _ip_allowed(ip, pinned):
        log.warning("shipper enrollment from %s outside its allowed ranges", ip)
        raise HTTPException(401, detail="Invalid enrollment code")
    prof = (await db.execute(select(CollectorProfile).where(CollectorProfile.id == enr.profile_id))).scalar_one_or_none()
    if prof is None:
        raise HTTPException(401, detail="Invalid enrollment code")
    _fingerprint(body.public_key)  # reject a junk key before burning the code
    # Atomic claim so two racing installers can't both mint a token from one code
    claimed = await db.execute(update(CollectorEnrollment).where(
        CollectorEnrollment.id == enr.id, CollectorEnrollment.used_at.is_(None)).values(used_at=now))
    if claimed.rowcount != 1:
        raise HTTPException(401, detail="Invalid enrollment code")
    return await _mint(db, prof, body.public_key, body.hostname, body.agent_version, ip, pinned)


@router.get("/info")
async def info(db: AsyncSession = Depends(get_session)):
    # Lets the installer's "test CTEM" step confirm it hit the right service before sending a password
    from api.collector.login import password_off
    from api.core.config import get_settings
    s = get_settings()
    return {"service": "open-ctem", "version": s.app_version,
            "password_login": not await password_off(db), "mfa_required": s.mfa_required}


@router.post("/login-check")
async def login_check(request: Request, db: AsyncSession = Depends(get_session)):
    from api.collector.login import check_admin_password, mfa_needed
    body: LoginCheckRequest = await _json_body(request, LoginCheckRequest)
    user = await check_admin_password(db, body.username, body.password)
    return {"ok": True, "mfa": mfa_needed(user)}


@router.post("/enroll-login")
async def enroll_login(request: Request, db: AsyncSession = Depends(get_session)):
    from api.collector.login import check_admin_password, check_mfa
    from api.core.security import _client_ip
    body: LoginEnrollRequest = await _json_body(request, LoginEnrollRequest)
    user = await check_admin_password(db, body.username, body.password)
    await check_mfa(user, body.totp)
    _fingerprint(body.public_key)
    prof = (await db.execute(select(CollectorProfile).where(CollectorProfile.name == body.name))).scalars().first()
    modules = service.clean_modules(body.modules, prof.modules if prof else None)
    if prof is None:
        prof = CollectorProfile(name=body.name, created_by=str(user.id), config_version=1)
        await service.one_per_fleet(db, prof, modules)   # before anything is added
        db.add(prof)
    prof.schedule_minutes = service.check_schedule(body.schedule_minutes)
    await service.save_profile_modules(db, prof, modules)
    log.info("shipper profile %s set up by admin %s from the box", body.name, user.id)
    return await _mint(db, prof, body.public_key, body.hostname, body.agent_version, _client_ip(request), [])


@router.post("/checkin")
async def checkin(request: Request, db: AsyncSession = Depends(get_session)):
    """Heartbeat + config pull in one: the box reports what it approved, CTEM answers with its profile."""
    tok = await ingest.authenticate(request, db)
    body: CheckinRequest = await _json_body(request, CheckinRequest)
    prof = await ingest.profile_of(tok, db)
    tok.collector_host, tok.agent_version = body.hostname, body.agent_version
    tok.approved = dict(body.approved)
    from api.auth.account_seal import seal_collector
    seal_collector(tok)   # what its own box approved, after it signed in with this credential
    if body.errors:
        await ingest.record_error(db, tok, prof, dict(body.errors))
    elif body.ran:
        tok.last_error = None
    config = service.agent_config(prof, await service.secrets_of(db, prof.id), tok)
    await db.commit()
    return config


@router.put("/secrets")
async def upload_secrets(request: Request, db: AsyncSession = Depends(get_session)):
    """Secrets typed on the box during install, already sealed to the box's own key."""
    tok = await ingest.authenticate(request, db)
    body: SecretsUpload = await _json_body(request, SecretsUpload)
    prof = await ingest.profile_of(tok, db)
    n = await service.store_secrets(db, prof, tok, body.secrets, f"shipper:{tok.collector_host or 'box'}")
    await db.commit()
    return {"stored": n}


@router.post("/ingest/{integration_id}")
async def ingest_batch(integration_id: str, request: Request, db: AsyncSession = Depends(get_session)):
    tok = await ingest.authenticate(request, db)
    batch = await _json_body(request, _Batch)
    cfg = await ingest.scoped_integration(tok, integration_id, batch.kind, db)
    from api.core.integration_truncate import running
    if await running(str(cfg.id)):
        raise HTTPException(409, detail="This source's data is being truncated; send again on the next run")
    from api.core import sync_pause
    if await sync_pause.paused(db):
        raise HTTPException(409, detail=sync_pause.MESSAGE)
    try:
        count = await ingest.apply_batch(db, batch, str(cfg.id))
        if getattr(batch, "spotlight_mode", None) == "full":
            await ingest.mark_full_spotlight(db, cfg, str(batch.run_id))
        job = await ingest.track_run(db, cfg, str(batch.run_id), count, batch.final, batch.warnings)
        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        log.exception("collector ingest failed for integration %s", integration_id)
        raise HTTPException(500, detail="Ingest failed") from None
    return {"accepted": count, "run_id": str(batch.run_id), "records": job.records_imported, "final": batch.final}


@router.get("/alerts/{integration_id}")
async def alert_feed(request: Request, db: AsyncSession = Depends(get_session), *, integration_id: str,
                     after: int = Query(-1, ge=-1, le=2**62)):
    """CTEM's alert feed for the box's own Splunk source, when that source forwards alerts (api/core/alert_feed.py).
    after=-1 starts from now: turning it on doesn't replay history."""
    from api.core import alert_feed
    tok = await ingest.authenticate(request, db)
    cfg = await ingest.scoped_integration(tok, integration_id, "splunk", db)
    prof = await ingest.profile_of(tok, db)
    mod = (prof.modules or {}).get("splunk") or {}
    if (mod.get("settings") or {}).get("forward_alerts", "off") == "off" or str(mod.get("integration_id")) != str(cfg.id):
        raise HTTPException(404)
    if after < 0:
        return {"alerts": [], "next": await alert_feed.latest_seq(db), "more": False}
    rows = await alert_feed.after(db, after, 500)
    return {"alerts": [r.event for r in rows], "next": rows[-1].seq if rows else after, "more": len(rows) == 500}



@router.get("/netprobe/{integration_id}/targets")
async def netprobe_targets(integration_id: str, request: Request, db: AsyncSession = Depends(get_session)):
    """What this shipper's network discovery should try: addresses nothing manages and their /24s (api/core/netprobe.py).
    Only for the shipper whose profile owns this integration; the box applies its own approved scope on top."""
    from api.core import netprobe
    tok = await ingest.authenticate(request, db)
    await ingest.scoped_integration(tok, integration_id, "netprobe", db)
    return await netprobe.targets(db)


class _ActionResult(_Strict):
    id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$")]
    ok: bool
    error: Annotated[str, StringConstraints(max_length=300)] | None = None


class _ActionResults(_Strict):
    results: list[_ActionResult] = Field(max_length=50)


async def _alert_updates_on(tok, integration_id: str, db: AsyncSession) -> None:
    """Only the shipper that owns this CrowdStrike source, with Alert updates turned on (and approved on its box)."""
    await ingest.scoped_integration(tok, integration_id, "crowdstrike", db)
    prof = await ingest.profile_of(tok, db)
    if (((prof.modules or {}).get("crowdstrike") or {}).get("settings") or {}).get("alert_updates") != "on":
        raise HTTPException(404)


@router.get("/alert-actions/{integration_id}")
async def alert_actions(integration_id: str, request: Request, db: AsyncSession = Depends(get_session)):
    """CrowdStrike alert updates people made in CTEM, for this shipper to send (api/core/cs_alert_actions.py)."""
    from api.core import cs_alert_actions
    tok = await ingest.authenticate(request, db)
    await _alert_updates_on(tok, integration_id, db)
    out = await cs_alert_actions.claim(db, integration_id)
    await db.commit()
    return {"actions": out}


@router.post("/alert-actions/{integration_id}/results")
async def alert_action_results(integration_id: str, request: Request, db: AsyncSession = Depends(get_session)):
    from api.core import cs_alert_actions
    tok = await ingest.authenticate(request, db)
    await _alert_updates_on(tok, integration_id, db)
    body: _ActionResults = await _json_body(request, _ActionResults)
    n = await cs_alert_actions.report(db, integration_id, [r.model_dump() for r in body.results])
    await db.commit()
    return {"recorded": n}


@router.get("/alert-refresh/{integration_id}")
async def alert_refresh(integration_id: str, request: Request, db: AsyncSession = Depends(get_session)):
    """CrowdStrike alerts CTEM has without their detail, for this shipper's CrowdStrike pull to fetch again by id
    (a read, the same Alerts API the pull uses; api/core/cs_alert_refresh.py)."""
    from api.core import cs_alert_refresh
    tok = await ingest.authenticate(request, db)
    await ingest.scoped_integration(tok, integration_id, "crowdstrike", db)
    ids = await cs_alert_refresh.due(db)
    await db.commit()
    return {"ids": ids}
