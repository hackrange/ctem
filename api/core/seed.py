"""First-boot seeder: built-in roles, permissions, and initial admin user.

Safe to call on every startup -- every step is idempotent.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

log = logging.getLogger("open-ctem.seed")

# name, display_name, description
_ROLES = [
    ("admin",     "Administrator",    "Full access to all features and settings"),
    ("cyber",     "Cyber Analyst",    "Read/write vulnerability, risk, and attack path data"),
    ("grc",       "GRC Analyst",      "Read/write GRC frameworks, exceptions, and suppliers"),
    ("it",        "IT Operations",    "Read device and CMDB data"),
    ("read_only", "Read Only",        "Read access across all dashboards"),
    ("service",   "Service Account",  "Machine-to-machine API access via tokens"),
]

# (resource, action, scope)
_PERMISSIONS = [
    ("admin",   "read",   "all"),
    ("admin",   "write",  "all"),
    ("users",   "read",   "all"),
    ("users",   "write",  "all"),
    ("devices", "read",   "all"),
    ("devices", "write",  "all"),
    ("vulns",   "read",   "all"),
    ("vulns",   "write",  "all"),
    ("grc",     "read",   "all"),
    ("grc",     "write",  "all"),
    ("reports", "read",   "all"),
    ("reports", "write",  "all"),
]


async def run_seed(db: AsyncSession, settings) -> None:
    await _seed_roles_and_perms(db)
    await _seed_admin_user(db, settings)
    await db.commit()


async def _seed_roles_and_perms(db: AsyncSession) -> None:
    from api.models.user import Permission, Role

    for resource, action, scope in _PERMISSIONS:
        exists = (await db.execute(
            select(Permission).where(
                Permission.resource == resource,
                Permission.action == action,
                Permission.scope == scope,
            )
        )).scalar_one_or_none()
        if not exists:
            db.add(Permission(resource=resource, action=action, scope=scope))

    await db.flush()

    for name, display, desc in _ROLES:
        exists = (await db.execute(
            select(Role).where(Role.name == name)
        )).scalar_one_or_none()
        if not exists:
            db.add(Role(name=name, display_name=display, description=desc, is_builtin=True))

    await db.flush()
    log.info("roles/permissions seeded")


async def _seed_admin_user(db: AsyncSession, settings) -> None:
    username = getattr(settings, "initial_admin_user", None)
    password = getattr(settings, "initial_admin_pass", None)
    if not username or not password:
        return

    from api.models.user import User, UserRole
    exists = (await db.execute(
        select(User).where(User.username == username)
    )).scalar_one_or_none()
    if exists:
        return

    from api.auth.local import hash_password
    user = User(
        username=username,
        display_name="Administrator",
        password_hash=hash_password(password),
        is_active=True,
        is_local=True,
    )
    db.add(user)
    await db.flush()
    db.add(UserRole(user_id=user.id, role_name="admin"))
    log.info("initial admin user '%s' created", username)
