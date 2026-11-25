"""On-prem shippers: GUI-managed profiles, sealed secrets, enrollment codes, and box credentials."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.core.encryption import EncryptedJSON, EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class CollectorProfile(Base, UUIDPrimaryKey, TimestampMixin):
    """What one shipper should pull and how often. Non-secret settings only."""
    __tablename__ = "collector_profiles"

    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    schedule_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    # {kind: {"enabled": bool, "integration_id": str, "settings": {...}}}; hostnames are sensitive enough to encrypt
    modules: Mapped[dict | None] = mapped_column(EncryptedJSON)
    config_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(36))


class CollectorSecret(Base, UUIDPrimaryKey, TimestampMixin):
    """A password sealed in the admin's browser to one shipper's public key. CTEM can't open it."""
    __tablename__ = "collector_secrets"

    profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    field: Mapped[str] = mapped_column(String(32), nullable=False)
    # Already end-to-end encrypted; wrapped again with the server key so a DB dump shows nothing useful
    envelope: Mapped[str] = mapped_column(EncryptedString("collector_secrets.envelope"), nullable=False)
    key_fp: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(64))


class CollectorEnrollment(Base, UUIDPrimaryKey, TimestampMixin):
    """Single-use code baked into a downloaded installer. Only the SHA-256 is kept."""
    __tablename__ = "collector_enrollments"

    profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Optional CIDRs the shipper egresses from; empty means pin whatever IP enrolls
    allowed_ips: Mapped[list | None] = mapped_column(EncryptedJSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(36))


class CollectorToken(Base, UUIDPrimaryKey, TimestampMixin):
    """The enrolled box: push token (hash only), its public key, and what it last reported."""
    __tablename__ = "collector_tokens"

    profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    key_fp: Mapped[str] = mapped_column(String(64), nullable=False)
    allowed_ips: Mapped[list | None] = mapped_column(EncryptedJSON, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    collector_host: Mapped[str | None] = mapped_column(EncryptedString)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_ip: Mapped[str | None] = mapped_column(String(45))
    last_error: Mapped[str | None] = mapped_column(String(500))
    # {kind: digest of the destination the box has approved}; compared against the profile for "pending"
    approved: Mapped[dict | None] = mapped_column(EncryptedJSON)
