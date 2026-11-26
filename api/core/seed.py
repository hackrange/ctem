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
    ("it_user",   "IT Operations",    "Read device and CMDB data"),
    ("read_only", "Read Only",        "Read access across all dashboards"),
    ("service",   "Service Account",  "Machine-to-machine API access via tokens"),
    ("no_access", "No Access", "Can sign in through SSO but sees only the access message; no permissions"),
    ("grc_integration", "GRC Integration", "Read-only GRC checks and evidence for FairTPRM's continuous monitors"),
    ("inventory", "Inventory",        "Sees every device; sets who it's assigned to and shipped, lost, stolen or returned"),
    ("idv_validation", "IDV Validation", "Service desk: sends a person an identity verification request and reads the result, nothing else"),
    ("idv_desk", "IDV Desk Embed", "The service desk embed's token: starts caller verification panels, nothing else"),
    ("idv_approvers", "IDV Approvers", "Approves, declines and revokes identity verifications; the only role that can"),
]

# (resource, action, scope)
_PERMISSIONS = [
    ("admin",    "read",   "all"),
    ("admin",    "write",  "all"),
    ("users",    "read",   "all"),
    ("users",    "write",  "all"),
    ("devices",  "read",   "all"),
    ("devices",  "write",  "all"),
    ("vulns",    "read",   "all"),
    ("vulns",    "write",  "all"),
    ("findings", "read",   "all"),
    ("findings", "write",  "all"),
    ("grc",      "read",   "all"),
    ("grc",      "write",  "all"),
    ("reports",  "read",   "all"),
    ("reports",  "write",  "all"),
    ("inventory", "write", "all"),
    ("idv", "request", "all"),   # start an identity verification for a person and read how it went
    ("idv", "approve", "all"),
    ("idv", "desk", "all"),
    ("idv", "send", "all"),      # send a person a re-verification link (IDV Approvers and IDV Validation)      # start a caller verification panel (the service desk embed's token only)   # approve, decline or revoke an identity verification (IDV Approvers only)
]

# role -> list of (resource, action) it gets
_ROLE_PERMS: dict[str, list[tuple[str, str]]] = {
    "admin": [
        ("admin", "read"), ("admin", "write"),
        ("users", "read"), ("users", "write"),
        ("devices", "read"), ("devices", "write"),
        ("vulns", "read"), ("vulns", "write"),
        ("findings", "read"), ("findings", "write"),
        ("grc", "read"), ("grc", "write"),
        ("reports", "read"), ("reports", "write"),
        ("inventory", "write"), ("idv", "request"),
    ],
    "cyber": [
        ("idv", "request"),
        ("devices", "read"), ("devices", "write"),
        ("vulns", "read"), ("vulns", "write"),
        ("findings", "read"), ("findings", "write"),
        ("grc", "read"), ("reports", "read"),
    ],
    "grc": [
        ("grc", "read"), ("grc", "write"),
        ("vulns", "read"), ("findings", "read"),
        ("reports", "read"), ("reports", "write"),
    ],
    "it_user": [
        ("devices", "read"), ("vulns", "read"),
        ("findings", "read"),
    ],
    "read_only": [
        ("devices", "read"), ("vulns", "read"),
        ("findings", "read"), ("grc", "read"),
        ("reports", "read"),
    ],
    "inventory": [
        ("devices", "read"), ("inventory", "write"),
    ],
    # FairTPRM's service token: control checks and evidence, nothing else
    "grc_integration": [("grc", "read")],
    # The service desk's token or people: identity verification requests only (api/routes/idv_desk.py)
    "idv_validation": [("idv", "request"), ("idv", "send")],
    # The only role that decides identity verifications; admin and cyber can see them, not decide
    "idv_approvers": [("idv", "approve"), ("idv", "send")],
    # An embed's token (api/routes/desk_admin.py): only POST/GET /api/v1/idv/desk/sessions (api/auth/middleware.py)
    "idv_desk": [("idv", "desk")],
    # Brand-new SSO people land here until an admin pins a real role
    "no_access": [],
    "service": [
        ("devices", "read"), ("devices", "write"),
        ("vulns", "read"), ("vulns", "write"),
        ("findings", "read"), ("findings", "write"),
    ],
}


async def run_seed(db: AsyncSession, settings) -> None:
    await _seed_roles_and_perms(db)
    await _seed_admin_user(db, settings)
    await _hold_unreviewed_learned_rules(db)
    await _idv_revoke_kinds(db)
    await db.commit()


async def _idv_revoke_kinds(db: AsyncSession) -> None:
    """People expired or revoked before 1.19.1 have no kind recorded: take it from their latest audit entry
    (idv.expire or idv.revoke), so an expire isn't treated as a revoke. Runs until none are left."""
    from api.models.settings import AuditLog
    from api.models.user import User
    for u in (await db.execute(select(User).where(User.idv_revoked_at.is_not(None), User.idv_revoked_kind.is_(None)))).scalars():
        act = (await db.execute(select(AuditLog.action).where(AuditLog.resource_id == u.id, AuditLog.action.in_(("idv.expire", "idv.revoke")))
                                .order_by(AuditLog.created_at.desc()).limit(1))).scalar_one_or_none()
        u.idv_revoked_kind = "expire" if act == "idv.expire" else "revoke"


async def _hold_unreviewed_learned_rules(db: AsyncSession) -> None:
    """Once, on upgrade: rules learned from a hunt before 1.11.2 went live unreviewed. Switch them off until an admin
    reviews them, as new learned rules now are. Rules people wrote, built-in and reviewed rules are untouched."""
    from sqlalchemy import update
    from api.models.settings import AppSetting
    from api.models.threat_rule import ThreatRule
    key = "migrate.learned_rules_held"
    if (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none() is not None:
        return
    await db.execute(update(ThreatRule).where(ThreatRule.status == "learned", ThreatRule.created_by == "ai",
                                              ThreatRule.enabled == True).values(enabled=False))  # noqa: E712
    db.add(AppSetting(key=key, value="1"))


async def _seed_roles_and_perms(db: AsyncSession) -> None:
    from api.models.user import Permission, Role, RolePermission

    # Upsert permissions, build lookup table
    perm_lookup: dict[tuple[str, str], str] = {}
    for resource, action, scope in _PERMISSIONS:
        existing = (await db.execute(
            select(Permission).where(
                Permission.resource == resource,
                Permission.action == action,
                Permission.scope == scope,
            )
        )).scalar_one_or_none()
        if not existing:
            existing = Permission(resource=resource, action=action, scope=scope)
            db.add(existing)
            await db.flush()
        perm_lookup[(resource, action)] = str(existing.id)

    # Upsert roles
    for name, display, desc in _ROLES:
        existing = (await db.execute(
            select(Role).where(Role.name == name)
        )).scalar_one_or_none()
        if not existing:
            db.add(Role(name=name, display_name=display, description=desc, is_builtin=True))

    await db.flush()

    # Wire role->permission assignments
    for role_name, pairs in _ROLE_PERMS.items():
        for resource, action in pairs:
            perm_id = perm_lookup.get((resource, action))
            if not perm_id:
                continue
            existing = (await db.execute(
                select(RolePermission).where(
                    RolePermission.role_name == role_name,
                    RolePermission.permission_id == perm_id,
                )
            )).scalar_one_or_none()
            if not existing:
                db.add(RolePermission(role_name=role_name, permission_id=perm_id))

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
    from api.auth.account_seal import reseal
    await reseal(db, user, ["admin"])
    log.info("initial admin user '%s' created", username)
