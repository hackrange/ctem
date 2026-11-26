"""IDV page > Iframe Code (admins): the places the caller verification panel may be shown, each with its own token.

Making one names the exact service desk site (https://acme.service-now.com), the server ranges the token works from
(the service desk platform's outbound addresses) and the analysts' network ranges. CTEM makes an IP-bound API token
for the IDV desk service account (role IDV Desk Embed: nothing but starting panels), shows it once with the code to
paste, and keeps only its hash. Revoking an embed turns its token off and ends its open panels at once."""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.idv import DeskEmbed, DeskSession
from api.models.settings import AuditLog
from api.models.user import ApiToken, User, UserRole

router = APIRouter(prefix="/api/v1/idv/desk", tags=["idv-desk"])
SERVICE_USER = "svc-idv-desk"
ROLE = "idv_desk"   # starts panels and reads their outcome; the middleware refuses this account everywhere else
RATE_PER_MIN = 120


def _nets(v: list[str], what: str, widest_v4: int) -> list[str]:
    out = []
    for raw in v:
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(f"not an IP or CIDR: {raw[:60]}") from None
        if net.prefixlen < (widest_v4 if net.version == 4 else widest_v4 + 32):
            raise ValueError(f"{raw} is too broad for {what}")
        out.append(str(net))
    if not out:
        raise ValueError(f"give at least one address range for {what}")
    return out[:30]


class NewEmbed(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9 ._\-()]+$")
    frame_origin: str = Field(max_length=256)
    server_ips: list[str] = Field(min_length=1, max_length=30)
    client_ips: list[str] = Field(min_length=1, max_length=30)
    expires_in_days: int = Field(365, ge=1, le=730)

    @field_validator("frame_origin")
    @classmethod
    def _origin(cls, v: str) -> str:
        from api.integrations.idv_config import desk_origins
        o = desk_origins({"desk_frame_origins": v}, strict=True)
        if len(o) != 1:
            raise ValueError("give exactly one https site, like https://acme.service-now.com")
        return o[0]

    @field_validator("server_ips")
    @classmethod
    def _server(cls, v):
        return _nets(v, "the service desk's servers", 16)

    @field_validator("client_ips")
    @classmethod
    def _client(cls, v):
        return _nets(v, "the analysts' network", 8)


async def _service_user(db: AsyncSession) -> User:
    """The account every embed's token acts as: no password, no SSO, one role (IDV Desk Embed), sealed."""
    user = (await db.execute(select(User).where(User.username == SERVICE_USER))).scalar_one_or_none()
    if user is None:
        user = User(username=SERVICE_USER, display_name="Service desk caller verification", is_local=True, is_active=True,
                    is_locked=False, is_service_account=True, password_hash=None)
        db.add(user)
        await db.flush()
    elif not user.is_service_account or user.oidc_sub or user.password_hash:
        raise HTTPException(409, detail=f"An account named {SERVICE_USER} exists that isn't the service account")
    roles = (await db.execute(select(UserRole).where(UserRole.user_id == str(user.id)))).scalars().all()
    for r in roles:
        if r.role_name != ROLE:
            await db.delete(r)
    if ROLE not in [r.role_name for r in roles]:
        db.add(UserRole(user_id=str(user.id), role_name=ROLE))
    user.is_active, user.is_locked, user.is_local, user.password_hash = True, False, True, None
    user.totp_enabled, user.totp_secret, user.totp_seal, user.recovery_codes = False, None, None, None
    user.oidc_sub = user.oidc_issuer = None
    from api.auth.account_seal import reseal
    await reseal(db, user, [ROLE])
    return user


def _view(e: DeskEmbed, t: ApiToken | None, n: int) -> dict:
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {"id": e.id, "name": e.name, "frame_origin": e.frame_origin, "server_ips": e.server_ips or [],
            "client_ips": e.client_ips or [], "created_by": e.created_by, "created_at": iso(e.created_at),
            "revoked_at": iso(e.revoked_at), "revoked_by": e.revoked_by, "sessions": n,
            "last_used": iso(t.last_used) if t else None, "expires_at": iso(t.expires_at) if t else None,
            "active": e.revoked_at is None and t is not None and t.is_active}


@router.get("/embeds")
async def list_embeds(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(DeskEmbed).order_by(DeskEmbed.revoked_at.is_not(None), DeskEmbed.created_at.desc()).limit(100))).scalars().all()
    toks = {t.id: t for t in (await db.execute(select(ApiToken).where(ApiToken.id.in_([e.token_id for e in rows if e.token_id])))).scalars()}
    counts = dict((await db.execute(select(DeskSession.embed_id, func.count()).where(DeskSession.embed_id.in_([e.id for e in rows]))
                                    .group_by(DeskSession.embed_id))).all())
    return {"embeds": [_view(e, toks.get(e.token_id), counts.get(e.id, 0)) for e in rows]}


@router.post("/embeds", status_code=201)
async def create_embed(body: NewEmbed, me: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.auth.account_seal import seal_token
    live = (await db.execute(select(func.count()).select_from(DeskEmbed).where(DeskEmbed.revoked_at.is_(None)))).scalar_one()
    if live >= 20:
        raise HTTPException(409, detail="That's twenty live embeds; revoke one you no longer use")
    svc = await _service_user(db)
    raw = secrets.token_hex(32)   # the API token format: 64 hex characters
    now = datetime.now(timezone.utc)
    tok = ApiToken(user_id=svc.id, name=f"Caller verification: {body.name}"[:128], description=f"Embed for {body.frame_origin}"[:256],
                   token_hash=hashlib.sha256(raw.encode()).hexdigest(), allowed_ips=body.server_ips,
                   expires_at=now + timedelta(days=body.expires_in_days), is_active=True, rate_limit_per_minute=RATE_PER_MIN)
    db.add(tok)
    await db.flush()
    seal_token(tok)
    e = DeskEmbed(name=body.name, frame_origin=body.frame_origin, server_ips=body.server_ips, client_ips=body.client_ips,
                  token_id=tok.id, created_by=me.username, created_at=now)
    db.add(e)
    await db.flush()
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="idv.embed_create", resource_type="desk_embed",
                    resource_id=e.id, detail=f"{body.name} for {body.frame_origin}"[:300]))
    await db.commit()
    return {**_view(e, tok, 0), "token": raw, "shown_once": True}


@router.post("/embeds/{embed_id}/revoke")
async def revoke_embed(embed_id: uuid.UUID, me: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.auth.account_seal import seal_token
    e = (await db.execute(select(DeskEmbed).where(DeskEmbed.id == str(embed_id)).with_for_update())).scalar_one_or_none()
    if e is None:
        raise HTTPException(404)
    now = datetime.now(timezone.utc)
    if e.revoked_at is None:
        e.revoked_at, e.revoked_by = now, me.username
    t = await db.get(ApiToken, e.token_id) if e.token_id else None
    if t is not None and t.is_active:
        t.is_active = False
        seal_token(t)
    await db.execute(update(DeskSession).where(DeskSession.embed_id == e.id, DeskSession.expires_at > now)
                     .values(expires_at=now, launch_expires_at=now))   # open panels end now
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="idv.embed_revoke", resource_type="desk_embed",
                    resource_id=e.id, detail=f"{e.name} for {e.frame_origin}"[:300]))
    await db.commit()
    return _view(e, t, 0)


@router.delete("/embeds/{embed_id}")
async def delete_embed(embed_id: uuid.UUID, me: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    """Remove a revoked embed for good: the embed, its (already off) token and its old panel sessions. A live one
    must be revoked first. The verifications it sent and the audit log stay, so what happened can still be traced."""
    from sqlalchemy import delete
    e = (await db.execute(select(DeskEmbed).where(DeskEmbed.id == str(embed_id)).with_for_update())).scalar_one_or_none()
    if e is None:
        raise HTTPException(404)
    if e.revoked_at is None:
        raise HTTPException(409, detail="Revoke this embed first; only a revoked embed can be deleted")
    if e.token_id:
        await db.execute(delete(ApiToken).where(ApiToken.id == e.token_id, ApiToken.is_active.is_(False)))
    await db.execute(delete(DeskSession).where(DeskSession.embed_id == e.id))
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="idv.embed_delete", resource_type="desk_embed",
                    resource_id=e.id, detail=f"{e.name} for {e.frame_origin} (revoked {e.revoked_at.date().isoformat()})"[:300]))
    await db.delete(e)
    await db.commit()
    return {"deleted": True}
