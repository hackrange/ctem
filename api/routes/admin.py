"""Admin routes: user management, role management, audit log, API tokens."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import require_admin
from api.auth import local as local_auth
from api.core.db import get_session
from api.core.encryption import search_hash
from api.models.user import ApiToken, Permission, Role, RolePermission, User, UserRole
from api.core.user_devices import NO_DEVICES as _NO_DEVICES
from api.core.user_devices import device_counts
from api.routes.user_view import user_summary as _user_summary
from api.models.settings import AuditLog

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/users")
async def list_users(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, description="Username prefix search"),
    cursor: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    stmt = select(User).options(selectinload(User.roles)).order_by(User.created_at.desc())
    if q:
        from api.core.encryption import search_hash
        stmt = stmt.where(or_(User.username.ilike(f"%{q}%"), User.upn_hash == search_hash(q.strip().lower())))
    if cursor:
        stmt = stmt.where(User.id < str(cursor))
    total_result = await db.execute(select(func.count(User.id)))
    total = total_result.scalar_one()
    stmt = stmt.offset(offset).limit(limit + 1)
    result = await db.execute(stmt)
    users = result.scalars().all()
    next_cursor = str(users[-1].id) if len(users) > limit else None

    # Enrich with risk scores
    from api.models.risk import RiskScore
    user_ids = [u.id for u in users[:limit]]
    scores_result = await db.execute(
        select(RiskScore).where(RiskScore.entity_type == "user", RiskScore.entity_id.in_(user_ids))
    )
    scores_by_id = {s.entity_id: s for s in scores_result.scalars()}
    devices_by_id = await device_counts(db, user_ids)

    return {
        "users": [{**_user_summary(u, scores_by_id.get(u.id)), **devices_by_id.get(u.id, _NO_DEVICES)}
                  for u in users[:limit]],
        "next_cursor": next_cursor,
        "total": total,
    }


@router.post("/users")
async def create_user(
    body: CreateUserRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, detail="Username already exists")
    await _require_roles_exist(body.roles, db)

    user = User(
        username=body.username,
        is_local=True,
        password_hash=local_auth.hash_password(body.password),
    )
    if body.email:
        user.email = body.email
        user.email_hash = search_hash(body.email)
    db.add(user)
    await db.flush()  # assigns user.id before UserRole FK
    for role in body.roles:
        db.add(UserRole(user_id=user.id, role_name=role))

    await db.commit()
    await db.refresh(user, attribute_names=["roles"])
    await _audit(admin, "create_user", "user", str(user.id), f"Created user {body.username}", db)
    return _user_summary(user)


@router.patch("/users/{user_id}/unlock")
async def unlock_user(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Clear both Redis lockout and DB flag. Admin only."""
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    await local_auth.admin_unlock_user(user.username)
    await _audit(admin, "unlock_user", "user", str(user_id), f"Unlocked {user.username}", db)
    return {"unlocked": True}


@router.patch("/users/{user_id}/toggle")
async def toggle_user_active(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Flip is_active for a user account. Can't deactivate yourself."""
    if str(user_id) == str(admin.id):
        raise HTTPException(400, detail="You can't deactivate your own account")
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    user.is_active = not user.is_active
    action = "activate_user" if user.is_active else "deactivate_user"
    await _audit(admin, action, "user", str(user_id), f"{action} {user.username}", db)
    await db.commit()
    return {"is_active": user.is_active}


@router.patch("/users/{user_id}/roles")
async def update_user_roles(
    user_id: uuid.UUID,
    body: UpdateRolesRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(User).options(selectinload(User.roles)).where(User.id == str(user_id))
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    await _require_roles_exist(body.roles, db)

    # Remove old roles, assign new
    for ur in user.roles:
        await db.delete(ur)
    for role_name in body.roles:
        db.add(UserRole(user_id=user.id, role_name=role_name))

    await db.commit()
    await _audit(admin, "update_user_roles", "user", str(user_id), f"Roles set to {body.roles}", db)
    return {"updated": True}


@router.patch("/users/{user_id}")
async def update_user(
    user_id: uuid.UUID,
    body: "UpdateUserRequest",
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Update user fields: email and/or password. Username changes not allowed."""
    from api.core.encryption import encrypt, search_hash as _search_hash
    result = await db.execute(
        select(User).options(selectinload(User.roles)).where(User.id == str(user_id))
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    if body.email is not None:
        user.email = body.email if body.email else None  # EncryptedString encrypts on write
        user.email_hash = _search_hash(body.email) if body.email else None
    if body.password:
        user.password_hash = local_auth.hash_password(body.password)
        user.is_locked = False
    await db.commit()
    await _audit(admin, "update_user", "user", str(user_id), f"Updated {user.username}", db)
    return _user_summary(user)


@router.post("/users/{user_id}/totp/setup")
async def admin_setup_totp(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Generate a new TOTP secret for a user. Returns QR code URI and secret."""
    from api.auth.local import generate_totp_secret, totp_provisioning_uri
    from api.core.encryption import encrypt
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    secret = generate_totp_secret()
    user.totp_secret = encrypt(secret)
    user.totp_enabled = True
    await db.commit()
    uri = totp_provisioning_uri(secret, user.username)
    await _audit(admin, "setup_totp", "user", str(user_id), f"Admin set up TOTP for {user.username}", db)
    return {"provisioning_uri": uri, "secret": secret, "qr_png": _qr_png_b64(uri)}


@router.delete("/users/{user_id}/totp")
async def admin_remove_totp(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Disable and clear TOTP for a user."""
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    user.totp_secret = None
    user.totp_enabled = False
    await db.commit()
    await _audit(admin, "remove_totp", "user", str(user_id), f"Removed TOTP for {user.username}", db)
    return {"totp_enabled": False}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    if str(user.id) == str(admin.id):
        raise HTTPException(400, detail="Cannot delete yourself")
    await db.delete(user)
    await db.commit()
    await _audit(admin, "delete_user", "user", str(user_id), f"Deleted {user.username}", db)
    return {"deleted": True}


# ── Roles ─────────────────────────────────────────────────────────────────────

@router.get("/roles")
async def list_roles(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(Role))
    return {"roles": [{"name": r.name, "display_name": r.display_name, "is_builtin": r.is_builtin} for r in result.scalars()]}


@router.post("/roles")
async def create_role(
    body: CreateRoleRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    if (await db.execute(select(Role).where(Role.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, detail="Role already exists")
    role = Role(name=body.name, display_name=body.display_name, description=body.description, is_builtin=False)
    db.add(role)
    await db.commit()
    await _audit(admin, "create_role", "role", body.name, f"Created role {body.name}", db)
    return {"created": body.name}


@router.post("/roles/{role_name}/duplicate")
async def duplicate_role(
    role_name: str,
    body: DuplicateRoleRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Role).options(selectinload(Role.permissions)).where(Role.name == role_name)
    )
    source = result.scalar_one_or_none()
    if source is None:
        raise HTTPException(404)
    if (await db.execute(select(Role).where(Role.name == body.new_name))).scalar_one_or_none():
        raise HTTPException(409, detail="Role already exists")
    new_role = Role(name=body.new_name, display_name=body.display_name or f"Copy of {source.display_name}", is_builtin=False)
    db.add(new_role)
    for rp in source.permissions:
        db.add(RolePermission(role_name=body.new_name, permission_id=rp.permission_id))
    await db.commit()
    await _audit(admin, "duplicate_role", "role", body.new_name, f"Duplicated {role_name} -> {body.new_name}", db)
    return {"created": body.new_name}


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit_log(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
    cursor: str | None = None,
    limit: int = Query(100, le=500),
):
    # Cursor is "<created_at>|<id>" of the last row shown: page by time, ties broken by id
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit + 1)
    if cursor:
        try:
            ts, last_id = cursor.split("|", 1)
            at = datetime.fromisoformat(ts)
        except ValueError:
            raise HTTPException(400, detail="Invalid cursor") from None
        stmt = stmt.where((AuditLog.created_at < at) | ((AuditLog.created_at == at) & (AuditLog.id < last_id[:36])))
    result = await db.execute(stmt)
    rows = result.scalars().all()
    last = rows[limit - 1] if len(rows) > limit else None
    next_cursor = f"{last.created_at.isoformat()}|{last.id}" if last else None
    return {
        "entries": [{"id": str(r.id), "actor": r.actor_username, "action": r.action, "resource": r.resource_type, "detail": r.detail, "at": r.created_at.isoformat()} for r in rows[:limit]],
        "next_cursor": next_cursor,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _qr_png_b64(uri: str) -> str:
    """Generate a QR code PNG as a base64 data URI -- no CDN needed."""
    import io, base64, qrcode
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


async def _audit(actor: User, action: str, resource_type: str, resource_id: str, detail: str, db: AsyncSession) -> None:
    db.add(AuditLog(actor_user_id=str(actor.id), actor_username=actor.username, action=action, resource_type=resource_type, resource_id=resource_id, detail=detail))
    await db.commit()


async def _require_roles_exist(roles: list[str], db: AsyncSession) -> None:
    found = set((await db.execute(select(Role.name).where(Role.name.in_(roles)))).scalars())
    missing = sorted(set(roles) - found)
    if missing:
        raise HTTPException(400, detail=f"Unknown role(s): {', '.join(missing)}")


# ── Pydantic schemas ──────────────────────────────────────────────────────────

_EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]{1,189}\.[A-Za-z]{2,}$"
_ROLE_PATTERN = r"^[a-z0-9_]{2,64}$"


class CreateUserRequest(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._@-]{2,64}$")
    password: str = Field(min_length=12, max_length=1024)
    email: str | None = Field(None, max_length=254, pattern=_EMAIL_PATTERN)
    roles: list[Annotated[str, Field(pattern=_ROLE_PATTERN)]] = Field(default=["read_only"], max_length=20)


class UpdateRolesRequest(BaseModel):
    roles: list[Annotated[str, Field(pattern=_ROLE_PATTERN)]] = Field(max_length=20)


class UpdateUserRequest(BaseModel):
    email: str | None = Field(None, max_length=254, pattern=r"^$|" + _EMAIL_PATTERN)
    password: str | None = Field(None, min_length=12, max_length=1024)


class CreateRoleRequest(BaseModel):
    name: str = Field(pattern=_ROLE_PATTERN)
    display_name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(None, max_length=512)


class DuplicateRoleRequest(BaseModel):
    new_name: str = Field(pattern=_ROLE_PATTERN)
    display_name: str | None = Field(None, max_length=128)


class UpdatePageTagsRequest(BaseModel):
    page_tags: list[str]  # e.g. ["identity", "grc", "vuln"]


# ── Page access management ────────────────────────────────────────────────────

@router.get("/page-policies")
async def list_page_policies(_: User = Depends(require_admin)):
    """All page slugs with their associated tags and default allowed roles."""
    from api.core.page_access import all_pages
    return {"pages": all_pages()}


@router.patch("/users/{user_id}/page-tags")
async def update_user_page_tags(
    user_id: str,
    body: UpdatePageTagsRequest,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Assign page access tags to a user. Tags grant access to pages whose tag list
    intersects -- without promoting the user to a full analyst role.
    Example: tags=["identity"] grants /identity; tags=["grc"] grants /grc.
    """
    result = await db.execute(select(User).where(User.id == str(user_id)))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404)

    # Sanitize -- lowercase alphanumeric + hyphens only
    cleaned = [t.lower().strip() for t in body.page_tags if t.strip()]
    cleaned = [t for t in cleaned if t.replace("-", "").isalnum()][:50]

    target.page_tags = cleaned or None
    await db.commit()
    await _audit(current_user, "update_page_tags", "user", str(target.id),
                 f"set page_tags={cleaned}", db)
    return {"user_id": user_id, "page_tags": cleaned}


# ── Branding ──────────────────────────────────────────────────────────────────

_BRAND_KEYS = {"title", "accent_color", "logo_url", "org_name"}

@router.get("/branding")
async def get_branding(db: AsyncSession = Depends(get_session)):
    """Return current branding settings. Public -- used by the login page too."""
    from api.models.settings import AppSetting
    result = await db.execute(select(AppSetting).where(AppSetting.key.in_([f"brand.{k}" for k in _BRAND_KEYS])))
    settings_map = {s.key.removeprefix("brand."): s.value for s in result.scalars()}
    return settings_map


@router.put("/branding", status_code=200)
async def set_branding(
    body: "BrandingRequest",
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    from api.models.settings import AppSetting
    pairs = {k: v for k, v in body.model_dump().items() if k in _BRAND_KEYS and v is not None}
    for key, val in pairs.items():
        full_key = f"brand.{key}"
        result = await db.execute(select(AppSetting).where(AppSetting.key == full_key))
        setting = result.scalar_one_or_none()
        if setting:
            setting.value = val
        else:
            db.add(AppSetting(key=full_key, value=val))
    await db.commit()
    await _audit(admin, "update_branding", "system", "branding", f"Keys: {list(pairs.keys())}", db)
    return {"updated": list(pairs.keys())}


@router.delete("/branding", status_code=200)
async def reset_branding(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    from api.models.settings import AppSetting
    result = await db.execute(select(AppSetting).where(AppSetting.key.like("brand.%")))
    for s in result.scalars():
        await db.delete(s)
    await db.commit()
    await _audit(admin, "reset_branding", "system", "branding", "Reset to defaults", db)
    return {"reset": True}


class BrandingRequest(BaseModel):
    # These land in a <style> block and an <img> on the public login page
    title: str | None = Field(None, max_length=128)
    accent_color: str | None = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    logo_url: str | None = Field(
        None, max_length=700_000,
        pattern=r"^(/[A-Za-z0-9._~/-]*|data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+)$",
    )
    org_name: str | None = Field(None, max_length=128)
