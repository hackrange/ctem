"""Role-based access control. Server-side, every handler. UI hiding is not security."""
from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.core.db import get_session
from api.models.user import Permission, Role, RolePermission, User
from api.auth.middleware import get_current_user

# Admin and Cyber bypass all tag-scope filters
_GLOBAL_SCOPE_ROLES = {"admin", "cyber", "inventory"}  # inventory tracks every machine, but can't touch findings


async def _load_user_permissions(user: User, db: AsyncSession) -> set[str]:
    """Return set of 'resource:action:scope' strings for this user's roles."""
    if not user.role_names:
        return set()
    result = await db.execute(
        select(RolePermission)
        .options(selectinload(RolePermission.permission))
        .where(RolePermission.role_name.in_(user.role_names))
    )
    perms: set[str] = set()
    for rp in result.scalars():
        p = rp.permission
        perms.add(f"{p.resource}:{p.action}:{p.scope}")
    return perms


def require_permission(resource: str, action: str) -> Callable:
    """
    Dependency factory. Returns a dependency that checks the current user
    has the given resource+action permission. Scope (all/own/tag) is validated
    at the route handler level where the object ID is available.
    """
    async def _check(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_session),
    ) -> User:
        perms = await _load_user_permissions(current_user, db)
        # Check any matching scope (all, own, tag)
        matches = {p for p in perms if p.startswith(f"{resource}:{action}:")}
        if not matches:
            raise HTTPException(403, detail="Insufficient permissions")
        return current_user
    return _check


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if "admin" not in current_user.role_names:
        raise HTTPException(403, detail="Admin access required")
    return current_user


def require_cyber_or_admin(current_user: User = Depends(get_current_user)) -> User:
    if not {"admin", "cyber"}.intersection(current_user.role_names):
        raise HTTPException(403, detail="Cyber or Admin access required")
    return current_user


async def can_access_device(user: User, device: Any, db: AsyncSession) -> bool:
    """
    Object-level authorization for a device.
    Admin/Cyber can see everything. Others must have a matching tag assignment.
    Returns False for no-access (caller should return 404, not 403, to prevent enumeration).
    """
    if set(user.role_names).intersection(_GLOBAL_SCOPE_ROLES):
        return True

    # Assigned to this user by a person (the sign-in-detected owner is a hint, never a grant)
    from api.models.device import DeviceAssignment as _Assigned
    if (await db.execute(select(_Assigned.id).where(_Assigned.device_id == device.id,
                                                    _Assigned.user_id == user.id))).first():
        return True

    # Check tag-based group access
    from api.models.tag import GroupTagAccess, Tag
    from api.models.device import DeviceTag

    # Tags assigned to this device
    device_tag_ids = {dt.tag_id for dt in device.tags} if device.tags else set()
    if not device_tag_ids:
        return False

    # Roles this user has that grant tag access
    result = await db.execute(
        select(GroupTagAccess).where(
            GroupTagAccess.role_name.in_(user.role_names),
            GroupTagAccess.tag_id.in_(device_tag_ids),
        )
    )
    return result.first() is not None


async def get_accessible_device_tag_ids(user: User, db: AsyncSession) -> list[uuid.UUID] | None:
    """
    Return tag IDs this user can see, or None if unrestricted (admin/cyber).
    Used to build WHERE clauses for list endpoints.
    """
    if set(user.role_names).intersection(_GLOBAL_SCOPE_ROLES):
        return None  # None = no filter, see everything

    from api.models.tag import GroupTagAccess
    result = await db.execute(
        select(GroupTagAccess.tag_id).where(GroupTagAccess.role_name.in_(user.role_names))
    )
    return [row[0] for row in result.all()]
