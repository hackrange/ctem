"""Admin routes: user management, role management, audit log, API tokens."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import require_admin
from api.auth import local as local_auth
from api.core.db import get_session
from api.core.encryption import search_hash
from api.models.user import ApiToken, Permission, Role, RolePermission, User, UserRole
from api.models.settings import AuditLog

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/users")
async def list_users(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(50, le=200),
):
    stmt = select(User).options(selectinload(User.roles)).order_by(User.created_at.desc())
    if search:
        stmt = stmt.where(User.email_hash == search_hash(search) | User.username.ilike(f"%{search}%"))
    if cursor:
        stmt = stmt.where(User.id < uuid.UUID(cursor))
    stmt = stmt.limit(limit + 1)
    result = await db.execute(stmt)
    users = result.scalars().all()
    next_cursor = str(users[-1].id) if len(users) > limit else None
    return {"users": [_user_summary(u) for u in users[:limit]], "next_cursor": next_cursor}


@router.post("/users")
async def create_user(
    body: CreateUserRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, detail="Username already exists")

    user = User(
        username=body.username,
        is_local=True,
        password_hash=local_auth.hash_password(body.password),
    )
    if body.email:
        user.email = body.email
        user.email_hash = search_hash(body.email)
    db.add(user)
    for role in body.roles:
        db.add(UserRole(user_id=user.id, role_name=role))

    await db.commit()
    await _audit(admin, "create_user", "user", str(user.id), f"Created user {body.username}", db)
    return _user_summary(user)


@router.patch("/users/{user_id}/unlock")
async def unlock_user(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    """Clear both Redis lockout and DB flag. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)
    await local_auth.admin_unlock_user(user.username)
    await _audit(admin, "unlock_user", "user", str(user_id), f"Unlocked {user.username}", db)
    return {"unlocked": True}


@router.patch("/users/{user_id}/roles")
async def update_user_roles(
    user_id: uuid.UUID,
    body: UpdateRolesRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(User).options(selectinload(User.roles)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404)

    # Remove old roles, assign new
    for ur in user.roles:
        await db.delete(ur)
    for role_name in body.roles:
        db.add(UserRole(user_id=user.id, role_name=role_name))

    await db.commit()
    await _audit(admin, "update_user_roles", "user", str(user_id), f"Roles set to {body.roles}", db)
    return {"updated": True}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(select(User).where(User.id == user_id))
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
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit + 1)
    if cursor:
        stmt = stmt.where(AuditLog.id < uuid.UUID(cursor))
    result = await db.execute(stmt)
    rows = result.scalars().all()
    next_cursor = str(rows[-1].id) if len(rows) > limit else None
    return {
        "entries": [{"id": str(r.id), "actor": r.actor_username, "action": r.action, "resource": r.resource_type, "detail": r.detail, "at": r.created_at.isoformat()} for r in rows[:limit]],
        "next_cursor": next_cursor,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _user_summary(u: User) -> dict:
    return {
        "id": str(u.id),
        "username": u.username,
        "is_active": u.is_active,
        "is_locked": u.is_locked,
        "is_local": u.is_local,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "roles": [ur.role_name for ur in u.roles],
    }


async def _audit(actor: User, action: str, resource_type: str, resource_id: str, detail: str, db: AsyncSession) -> None:
    db.add(AuditLog(actor_user_id=str(actor.id), actor_username=actor.username, action=action, resource_type=resource_type, resource_id=resource_id, detail=detail))
    await db.commit()


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    username: str
    password: str
    email: str | None = None
    roles: list[str] = ["read_only"]


class UpdateRolesRequest(BaseModel):
    roles: list[str]


class CreateRoleRequest(BaseModel):
    name: str
    display_name: str
    description: str | None = None


class DuplicateRoleRequest(BaseModel):
    new_name: str
    display_name: str | None = None


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
    result = await db.execute(select(User).where(User.id == user_id))
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
