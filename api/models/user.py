from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
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

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)   # users, devices, vulns, admin...
    action: Mapped[str] = mapped_column(String(32), nullable=False)      # read, write, delete, export
    scope: Mapped[str] = mapped_column(String(32), default="all")        # all, own, tag
    description: Mapped[str | None] = mapped_column(Text)

    roles: Mapped[list[RolePermission]] = relationship(back_populates="permission")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_name: Mapped[str] = mapped_column(ForeignKey("roles.name", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

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
    totp_secret: Mapped[str | None] = mapped_column(EncryptedString)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    recovery_codes: Mapped[list | None] = mapped_column(EncryptedJSON)      # list of Argon2id-hashed recovery codes
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_local: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ad_dn: Mapped[str | None] = mapped_column(EncryptedString)
    ad_username: Mapped[str | None] = mapped_column(String(256), index=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Hard lockout flag (Redis handles timed lockouts; this is permanent until admin clears)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    locked_reason: Mapped[str | None] = mapped_column(String(256))
    # OIDC subject identifier
    oidc_sub: Mapped[str | None] = mapped_column(String(256), index=True)

    # AD / LDAP enrichment -- written by LDAP connector, used in user risk scoring
    ad_groups: Mapped[list | None] = mapped_column(EncryptedJSON)         # group names, encrypted at rest
    is_service_account: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Tag-based page access -- admins assign tags like ["identity","grc"] to let
    # restricted roles access specific dashboards without a full analyst role
    page_tags: Mapped[list | None] = mapped_column(EncryptedJSON, default=None)

    roles: Mapped[list[UserRole]] = relationship(back_populates="user", cascade="all, delete-orphan")

    @property
    def role_names(self) -> list[str]:
        return [ur.role_name for ur in self.roles]

    @property
    def allowed_page_tags(self) -> list[str]:
        return self.page_tags or []


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_name: Mapped[str] = mapped_column(ForeignKey("roles.name", ondelete="CASCADE"), primary_key=True)

    user: Mapped[User] = relationship(back_populates="roles")
    role: Mapped[Role] = relationship(back_populates="users")


class ApiToken(Base, UUIDPrimaryKey, TimestampMixin):
    """Long-lived API tokens. Each token is bound to one or more allowed source IPs."""
    __tablename__ = "api_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(256))
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # SHA-256
    # JSON list of allowed source IPs/CIDRs -- token only works from these addresses
    allowed_ips: Mapped[list | None] = mapped_column(EncryptedJSON, nullable=False)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_ip: Mapped[str | None] = mapped_column(String(45))  # last IP that used this token
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped[User] = relationship()
