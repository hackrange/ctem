"""Admin side of shippers: profiles, sealed secrets, installers, revocation. Admin only, server-side."""
from __future__ import annotations

import ipaddress
import logging
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.collector import ingest, service
from api.collector.installer import public_url, render_installer
from api.collector.schemas import SecretsUpload
from api.core.db import get_session
from api.models.collector import CollectorEnrollment, CollectorProfile, CollectorSecret, CollectorToken
from api.models.user import User

log = logging.getLogger("open-ctem.collector")
router = APIRouter(prefix="/api/v1/collectors", tags=["collectors"])


class ProfileCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    schedule_minutes: int = 60
    modules: dict[str, dict] = Field(min_length=1, max_length=4)


class ProfileUpdate(BaseModel):
    schedule_minutes: int | None = None
    modules: dict[str, dict] | None = Field(None, min_length=1, max_length=4)


class InstallerRequest(BaseModel):
    allowed_cidrs: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("allowed_cidrs")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        out = []
        for raw in v:
            raw = raw.strip()
            if not raw:
                continue
            try:
                out.append(str(ipaddress.ip_network(raw, strict=False)))
            except ValueError:
                raise ValueError("allowed_cidrs must be IPs or CIDR ranges") from None
        return out


def _uuid(val: str) -> str:
    try:
        return str(uuid.UUID(val))
    except ValueError:
        raise HTTPException(404) from None


async def _profile(db: AsyncSession, profile_id: str) -> CollectorProfile:
    prof = (await db.execute(select(CollectorProfile).where(CollectorProfile.id == _uuid(profile_id)))).scalar_one_or_none()
    if prof is None:
        raise HTTPException(404)
    return prof


async def _view(db: AsyncSession, prof: CollectorProfile) -> dict:
    tok = await service.active_token(db, prof.id)
    view = service.admin_view(prof, tok, await service.secrets_of(db, prof.id))
    pending = (await db.execute(select(CollectorEnrollment).where(
        CollectorEnrollment.profile_id == prof.id, CollectorEnrollment.used_at.is_(None)))).scalars().all()
    view["pending_installers"] = [{"id": str(e.id), "expires_at": e.expires_at.isoformat()} for e in pending]
    return view


def _script(script: str, filename: str) -> Response:
    return Response(content=script, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("")
async def list_profiles(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    profs = (await db.execute(select(CollectorProfile).order_by(CollectorProfile.name))).scalars().all()
    return {"shippers": [await _view(db, p) for p in profs]}


@router.post("", status_code=201)
async def create_profile(body: ProfileCreate, user: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    if (await db.execute(select(CollectorProfile).where(CollectorProfile.name == body.name))).scalars().first():
        raise HTTPException(409, detail="A shipper with that name exists")
    prof = CollectorProfile(name=body.name, schedule_minutes=service.check_schedule(body.schedule_minutes),
                            created_by=str(user.id), config_version=1)
    modules = service.clean_modules(body.modules)
    await service.one_per_fleet(db, prof, modules)   # before anything is added, so a refusal leaves nothing behind
    db.add(prof)
    await service.save_profile_modules(db, prof, modules)
    await db.commit()
    log.info("shipper profile %s created by %s", prof.name, user.id)
    return await _view(db, prof)


@router.get("/{profile_id}")
async def get_profile(profile_id: str, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    return await _view(db, await _profile(db, profile_id))


@router.put("/{profile_id}")
async def update_profile(profile_id: str, body: ProfileUpdate, user: User = Depends(require_admin),
                         db: AsyncSession = Depends(get_session)):
    prof = await _profile(db, profile_id)
    if body.schedule_minutes is not None:
        prof.schedule_minutes = service.check_schedule(body.schedule_minutes)
        prof.config_version = (prof.config_version or 1) + 1
    if body.modules is not None:
        modules = service.clean_modules(body.modules, prof.modules)
        dropped = set(prof.modules or {}) - set(modules)
        if dropped:
            await db.execute(delete(CollectorSecret).where(
                CollectorSecret.profile_id == prof.id, CollectorSecret.kind.in_(dropped)))
        await service.save_profile_modules(db, prof, modules)
    await db.commit()
    log.info("shipper profile %s updated by %s", prof.name, user.id)
    return await _view(db, prof)


@router.put("/{profile_id}/secrets")
async def set_secrets(profile_id: str, body: SecretsUpload, user: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_session)):
    """Envelopes sealed in the admin's browser. We check the shape and the key id, never the contents."""
    prof = await _profile(db, profile_id)
    n = await service.store_secrets(db, prof, await service.active_token(db, prof.id), body.secrets, user.username)
    await db.commit()
    log.info("shipper %s: %d sealed secret(s) rotated by %s", prof.name, n, user.id)
    return {"stored": n}


@router.post("/{profile_id}/installer")
async def profile_installer(profile_id: str, body: InstallerRequest, request: Request,
                            user: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    prof = await _profile(db, profile_id)
    url = public_url(request) or ""  # unknown means the box gets asked for it
    # One live code per profile; older downloads stop working
    await db.execute(delete(CollectorEnrollment).where(
        CollectorEnrollment.profile_id == prof.id, CollectorEnrollment.used_at.is_(None)))
    code = secrets.token_hex(32)
    db.add(CollectorEnrollment(profile_id=prof.id, code_hash=ingest.hash_secret(code),
                               allowed_ips=body.allowed_cidrs or None, expires_at=ingest.enrollment_expiry(),
                               created_by=str(user.id)))
    await db.commit()
    log.info("installer for shipper %s issued by %s", prof.name, user.id)
    return _script(render_installer(url, code, prof.name), f"open-ctem-shipper-{prof.name}.sh")


@router.post("/installer")
async def generic_installer(request: Request, _: User = Depends(require_admin)):
    """No code inside: the box signs in with an admin account and describes itself."""
    return _script(render_installer(public_url(request) or "", "", ""), "open-ctem-shipper.sh")


@router.post("/{profile_id}/revoke")
async def revoke_shipper(profile_id: str, user: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    """Box lost or rebuilt: kill its token, keep the profile so a fresh install can pick it up."""
    prof = await _profile(db, profile_id)
    for t in (await db.execute(select(CollectorToken).where(
            CollectorToken.profile_id == prof.id, CollectorToken.is_active == True))).scalars():  # noqa: E712
        t.is_active = False
        from api.auth.account_seal import seal_collector
        seal_collector(t)
    await db.commit()
    log.info("shipper %s revoked by %s", prof.name, user.id)
    return {"revoked": True}


@router.delete("/{profile_id}")
async def delete_profile(profile_id: str, user: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    prof = await _profile(db, profile_id)
    for model in (CollectorToken, CollectorSecret, CollectorEnrollment):
        await db.execute(delete(model).where(model.profile_id == prof.id))
    await db.delete(prof)
    await db.commit()
    log.info("shipper %s deleted by %s", prof.name, user.id)
    return {"deleted": True}
