"""Admin issues the token FairTPRM uses to read CTEM's control checks. Read-only, IP-bound, one at a time."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import ApiToken, User, UserRole

log = logging.getLogger("open-ctem.grc")
router = APIRouter(prefix="/api/v1/grc", tags=["grc"])

SERVICE_USER = "svc-fairtprm-grc"
ROLE = "grc_integration"
RATE_PER_MIN = 120


class ServiceTokenRequest(BaseModel):
    allowed_ips: list[str] = Field(min_length=1, max_length=20)
    expires_in_days: int = Field(365, ge=1, le=730)

    @field_validator("allowed_ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        out = []
        for raw in v:
            raw = raw.strip()
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                raise ValueError(f"not an IP or CIDR: {raw[:60]}") from None
            # A token that works from half the internet isn't IP-bound
            if net.prefixlen < (16 if net.version == 4 else 48):
                raise ValueError(f"{raw} is too broad; use the FairTPRM server's address")
            out.append(str(net) if "/" in raw else str(net.network_address))
        return out


async def _service_user(db: AsyncSession) -> User:
    user = (await db.execute(select(User).where(User.username == SERVICE_USER))).scalar_one_or_none()
    if user is None:
        # No password: this account can only ever act through its API token
        user = User(username=SERVICE_USER, display_name="FairTPRM continuous monitors", is_local=True,
                    is_active=True, is_locked=False, is_service_account=True, password_hash=None)
        db.add(user)
        await db.flush()
    # Exactly one role, and it's the read-only GRC one, whatever someone set by hand
    roles = (await db.execute(select(UserRole).where(UserRole.user_id == str(user.id)))).scalars().all()
    for r in roles:
        if r.role_name != ROLE:
            await db.delete(r)
    if ROLE not in [r.role_name for r in roles]:
        db.add(UserRole(user_id=str(user.id), role_name=ROLE))
    user.is_active, user.is_locked = True, False
    return user


@router.post("/fairtprm-token", status_code=201)
async def issue_fairtprm_token(body: ServiceTokenRequest, request: Request,
                               admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    user = await _service_user(db)
    for old in (await db.execute(select(ApiToken).where(ApiToken.user_id == str(user.id),
                                                         ApiToken.is_active == True))).scalars():  # noqa: E712
        old.is_active = False
    plain = secrets.token_hex(32)
    tok = ApiToken(user_id=str(user.id), name="FairTPRM continuous monitors",
                   description="Reads CTEM control checks and evidence; issued from the GRC page",
                   token_hash=hashlib.sha256(plain.encode()).hexdigest(), allowed_ips=body.allowed_ips,
                   expires_at=datetime.now(timezone.utc) + timedelta(days=body.expires_in_days),
                   is_active=True, rate_limit_per_minute=RATE_PER_MIN)
    db.add(tok)
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="grc_service_token_issued",
                    resource_type="api_token", detail=f"for {SERVICE_USER}, ips {', '.join(body.allowed_ips)}"))
    await db.commit()
    log.info("FairTPRM GRC token issued by %s for %s", admin.id, body.allowed_ips)
    from api.collector.installer import public_url
    return {"token": plain, "ctem_url": public_url(request) or "", "allowed_ips": body.allowed_ips,
            "expires_at": tok.expires_at.isoformat(), "account": SERVICE_USER,
            "warning": "Shown once. Paste it into FairTPRM's open-ctem integration; issuing a new one revokes this."}


@router.delete("/fairtprm-token", status_code=200)
async def revoke_fairtprm_token(admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    user = (await db.execute(select(User).where(User.username == SERVICE_USER))).scalar_one_or_none()
    n = 0
    if user is not None:
        for t in (await db.execute(select(ApiToken).where(ApiToken.user_id == str(user.id),
                                                           ApiToken.is_active == True))).scalars():  # noqa: E712
            t.is_active, n = False, n + 1
        db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="grc_service_token_revoked",
                        resource_type="api_token", detail=f"{n} token(s) for {SERVICE_USER}"))
        await db.commit()
    return {"revoked": n}
