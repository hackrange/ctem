"""API token management, admins only. Tokens are the only way to authenticate the REST API."""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import _client_ip
from api.auth.rbac import require_admin
from api.core.accounts import ctem_account, find_login
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import ApiToken, User

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])

_MAX_TOKENS_PER_USER = 20


@router.get("")
async def list_tokens(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """List all active tokens for the current user. Never returns the token value."""
    result = await db.execute(
        select(ApiToken).where(
            ApiToken.user_id == current_user.id,
            ApiToken.is_active == True,  # noqa: E712
        )
    )
    tokens = result.scalars().all()
    return {"tokens": [_serialize(t) for t in tokens]}


@router.post("", status_code=201)
async def create_token(
    body: CreateTokenRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Create an IP-bound API token. The plain token is returned ONCE -- store it securely.
    If no allowed_ips are provided, the caller's current IP is used.
    """
    owner = current_user
    if body.owner_username and body.owner_username.strip().lower() != current_user.username.lower():
        owner = await find_login(db, body.owner_username, ctem_account(), options=[selectinload(User.roles)])
        if owner is None or not owner.is_active or owner.is_locked or not owner.role_names:
            raise HTTPException(400, detail="No active CTEM account with that username")

    # Cap tokens per user to prevent abuse
    count_result = await db.execute(
        select(ApiToken).where(ApiToken.user_id == owner.id, ApiToken.is_active == True)  # noqa: E712
    )
    if len(count_result.scalars().all()) >= _MAX_TOKENS_PER_USER:
        raise HTTPException(400, detail=f"Maximum {_MAX_TOKENS_PER_USER} active tokens per user")

    # Default to caller's current IP if none specified
    caller_ip = _client_ip(request)
    allowed_ips = body.allowed_ips if body.allowed_ips else [caller_ip]

    plain_token = secrets.token_hex(32)  # 64-char hex, 256 bits
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    api_token = ApiToken(
        user_id=owner.id,
        name=body.name,
        description=body.description,
        token_hash=token_hash,
        allowed_ips=allowed_ips,
        expires_at=expires_at,
        is_active=True,
        rate_limit_per_minute=body.rate_limit_per_minute,
    )
    db.add(api_token)
    db.add(AuditLog(actor_user_id=str(current_user.id), actor_username=current_user.username, action="api_token_created",
                    resource_type="api_token", detail=f"token {body.name!r} for {owner.username}", ip_address=caller_ip))
    await db.commit()
    await db.refresh(api_token)

    return {
        **_serialize(api_token),
        "token": plain_token,  # only time this is ever returned
        "warning": "Save this token now. It will never be shown again.",
    }


@router.patch("/{token_id}/ips")
async def update_token_ips(
    token_id: str,
    body: UpdateIpsRequest,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Replace the allowed IP list for a token."""
    token = await _get_own_token(token_id, current_user, db)
    token.allowed_ips = body.allowed_ips
    await db.commit()
    return _serialize(token)


@router.delete("/{token_id}", status_code=204)
async def revoke_token(
    token_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Revoke a token. Admins can revoke any token."""
    if "admin" in current_user.role_names:
        result = await db.execute(select(ApiToken).where(ApiToken.id == _parse_uuid(token_id)))
    else:
        result = await db.execute(
            select(ApiToken).where(ApiToken.id == _parse_uuid(token_id), ApiToken.user_id == current_user.id)
        )
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(404)
    token.is_active = False
    await db.commit()


@router.get("/admin/all")
async def admin_list_all_tokens(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Admin: list all active tokens across all users."""
    result = await db.execute(select(ApiToken).where(ApiToken.is_active == True))  # noqa: E712
    return {"tokens": [_serialize(t) for t in result.scalars().all()]}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_own_token(token_id: str, user: User, db: AsyncSession) -> ApiToken:
    result = await db.execute(
        select(ApiToken).where(ApiToken.id == _parse_uuid(token_id), ApiToken.user_id == user.id)
    )
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(404)
    return token


def _parse_uuid(val: str) -> str:
    import uuid
    try:
        return str(uuid.UUID(val))
    except ValueError:
        raise HTTPException(404)


def _serialize(t: ApiToken) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "description": t.description,
        "allowed_ips": t.allowed_ips or [],
        "last_used": t.last_used.isoformat() if t.last_used else None,
        "last_used_ip": t.last_used_ip,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "rate_limit_per_minute": t.rate_limit_per_minute,
    }


def _validate_ip_list(ips: list[str]) -> list[str]:
    cleaned = []
    for entry in ips:
        try:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
            else:
                ipaddress.ip_address(entry)
            cleaned.append(entry)
        except ValueError:
            raise ValueError(f"Invalid IP or CIDR: {entry!r}")
    return cleaned


class CreateTokenRequest(BaseModel):
    name: str
    description: str | None = None
    allowed_ips: list[str] | None = None   # defaults to caller's IP
    expires_in_days: int | None = None
    rate_limit_per_minute: int | None = None  # None = global default
    # Admins mint tokens for anyone (e.g. an inventory account a script runs as); blank means the admin
    owner_username: str | None = Field(None, max_length=128)

    @field_validator("allowed_ips")
    @classmethod
    def validate_ips(cls, v):
        if v is not None:
            return _validate_ip_list(v)
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if not v or len(v.strip()) < 2:
            raise ValueError("Token name must be at least 2 characters")
        return v.strip()[:128]


class UpdateIpsRequest(BaseModel):
    allowed_ips: list[str]

    @field_validator("allowed_ips")
    @classmethod
    def validate_ips(cls, v):
        if not v:
            raise ValueError("Must provide at least one IP")
        return _validate_ip_list(v)
