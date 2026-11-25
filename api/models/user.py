from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.encryption import EncryptedJSON, EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class Role(Base):
    """Built-in and custom roles. Built-in roles cannot be deleted."""
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    permissions: Mapped[list[RolePermission]] = relationship(back_populates="role", cascade="all, delete-orphan")
    users: Mapped[list[UserRole]] = relationship(back_populates="role", cascade="all, delete-orphan")


class Permission(Base):
    """Granular permission: resource + action + scope."""
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("resource", "action", "scope", name="uq_perm"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    resource: Mapped[str] = mapped_column(String(64), nullable=False)   # users, devices, vulns, admin...
    action: Mapped[str] = mapped_column(String(32), nullable=False)      # read, write, delete, export
    scope: Mapped[str] = mapped_column(String(32), default="all")        # all, own, tag
    description: Mapped[str | None] = mapped_column(Text)

    roles: Mapped[list[RolePermission]] = relationship(back_populates="permission")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_name: Mapped[str] = mapped_column(ForeignKey("roles.name", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[str] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

    role: Mapped[Role] = relationship(back_populates="permissions")
    permission: Mapped[Permission] = relationship(back_populates="roles")


class User(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_username"),)

    username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(EncryptedString)
    email_hash: Mapped[str | None] = mapped_column(String(64), index=True)  # HMAC for search
    display_name: Mapped[str | None] = mapped_column(EncryptedString)
    password_hash: Mapped[str | None] = mapped_column(Text)                 # Argon2id; null for OIDC-only users
    totp_secret: Mapped[str | None] = mapped_column(EncryptedString("users.totp_secret"))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_seal: Mapped[str | None] = mapped_column(String(64))   # keyed seal tying totp_secret to this account
    auth_seal: Mapped[str | None] = mapped_column(String(64))   # keyed seal over sign-in state and roles (account_seal)
    recovery_codes: Mapped[list | None] = mapped_column(EncryptedJSON)      # list of Argon2id-hashed recovery codes
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_local: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ad_dn: Mapped[str | None] = mapped_column(EncryptedString)
    ad_username: Mapped[str | None] = mapped_column(String(256), index=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # A browser session that signed in before this no longer counts (set by a new password; api/auth/sessions.py)
    sessions_valid_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Hard lockout flag (Redis handles timed lockouts; this is permanent until admin clears)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # A password an admin set is a one-time key: replaced at the first sign-in, and no good after it expires
    password_change_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    password_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    locked_reason: Mapped[str | None] = mapped_column(String(256))
    # OIDC subject identifier
    oidc_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    # The IdP that subject belongs to: a subject is only unique within its issuer (empty on accounts from before this)
    oidc_issuer: Mapped[str | None] = mapped_column(String(512))

    # AD / LDAP enrichment -- written by LDAP connector, used in user risk scoring
    ad_groups: Mapped[list | None] = mapped_column(EncryptedJSON)         # group names, encrypted at rest
    # AD account health, from the directory feed (risk signals, not CTEM sign-in state)
    ad_disabled: Mapped[bool | None] = mapped_column(Boolean)
    ad_last_logon: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ad_pwd_last_set: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ad_pwd_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ad_pwd_expired: Mapped[bool | None] = mapped_column(Boolean)
    ad_pwd_never_expires: Mapped[bool | None] = mapped_column(Boolean)
    ad_locked_out: Mapped[bool | None] = mapped_column(Boolean)
    # Directory profile (personal data, so encrypted at rest like display_name)
    first_name: Mapped[str | None] = mapped_column(EncryptedString)
    upn: Mapped[str | None] = mapped_column(EncryptedString)                 # userPrincipalName, jdoe@ad.acme.example
    upn_hash: Mapped[str | None] = mapped_column(String(64), index=True)    # HMAC of the lowercased UPN, for search
    last_name: Mapped[str | None] = mapped_column(EncryptedString)
    title: Mapped[str | None] = mapped_column(EncryptedString)
    phone: Mapped[str | None] = mapped_column(EncryptedString)   # +15550100199 when it parses, else as entered
    mobile: Mapped[str | None] = mapped_column(EncryptedString)
    # Where they work, from the directory: points CTEM at the office of the machines they sign in to
    office: Mapped[str | None] = mapped_column(EncryptedString)
    city: Mapped[str | None] = mapped_column(EncryptedString)
    state: Mapped[str | None] = mapped_column(EncryptedString)
    postal_code: Mapped[str | None] = mapped_column(EncryptedString)
    department: Mapped[str | None] = mapped_column(EncryptedString)
    is_service_account: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # From the identity provider (Okta): the phone the person verifies MFA with, and their account and MFA state
    mfa_phone: Mapped[str | None] = mapped_column(EncryptedString)
    idp: Mapped[dict | None] = mapped_column(EncryptedJSON)

    # Tag-based page access -- admins assign tags like ["identity","grc"] to let
    # restricted roles access specific dashboards without a full analyst role
    page_tags: Mapped[list | None] = mapped_column(EncryptedJSON, default=None)

    # UI/accessibility preferences: theme, font_size, high_contrast, etc.
    ui_prefs: Mapped[dict | None] = mapped_column(EncryptedJSON, default=None)

    roles: Mapped[list[UserRole]] = relationship(back_populates="user", cascade="all, delete-orphan")

    @property
    def role_names(self) -> list[str]:
        return [ur.role_name for ur in self.roles]

    @property
    def allowed_page_tags(self) -> list[str]:
        return self.page_tags or []


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_name: Mapped[str] = mapped_column(ForeignKey("roles.name", ondelete="CASCADE"), primary_key=True)

    user: Mapped[User] = relationship(back_populates="roles")
    role: Mapped[Role] = relationship(back_populates="users")


class ApiToken(Base, UUIDPrimaryKey, TimestampMixin):
    """Long-lived API tokens. Each token is bound to one or more allowed source IPs."""
    __tablename__ = "api_tokens"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(256))
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # SHA-256
    # JSON list of allowed source IPs/CIDRs -- token only works from these addresses
    allowed_ips: Mapped[list | None] = mapped_column(EncryptedJSON, nullable=False)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_ip: Mapped[str | None] = mapped_column(String(45))  # last IP that used this token
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Per-token rate limit; None means fall back to global setting
    rate_limit_per_minute: Mapped[int | None] = mapped_column(nullable=True)
    seal: Mapped[str | None] = mapped_column(String(64))   # keyed seal over the token row (api/auth/account_seal.py)

    user: Mapped[User] = relationship()


class EndedSession(Base):
    """A signed-out browser session, kept until it would have expired anyway. Redis answers first; this is read only
    when Redis can't be, so a signed-out cookie stays dead through a Redis outage (api/auth/sessions.py)."""
    __tablename__ = "ended_sessions"

    sid_hash: Mapped[str] = mapped_column(String(64), primary_key=True)   # SHA-256 of the session id
    until: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)   # UTC
