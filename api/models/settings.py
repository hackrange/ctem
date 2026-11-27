"""Application settings, immutable audit log, and AI usage metering."""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, validates

from api.core.encryption import EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class AppSetting(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def safe_value(self):
        return "[redacted]" if self.is_sensitive else self.value


class AuditLog(Base):
    """Append-only. Never update or delete rows from this table."""
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(_uuid.uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(EncryptedString, nullable=True)

    @validates("resource_id")
    def _fits(self, _key, value):
        """A resource id longer than the column (a CrowdStrike alert key is about 110 characters) is recorded as its
        UUIDv5: the same id every time for the same resource, so it can still be searched, never a failed write that
        takes the change it records down with it. Callers put the readable name in detail."""
        if isinstance(value, str) and len(value) > 36:
            return str(_uuid.uuid5(_uuid.NAMESPACE_URL, value))
        return value


class AIUsage(Base):
    """One row per AI call (including failures). Token counts only; never prompt or answer text."""
    __tablename__ = "ai_usage"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(_uuid.uuid4()))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, index=True)   # hunt, threat_analysis, test...
    provider: Mapped[str] = mapped_column(String(32), nullable=False)              # anthropic, openai, custom_ai, bedrock
    model: Mapped[str | None] = mapped_column(String(128), index=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    finish: Mapped[str | None] = mapped_column(String(32))                         # end_turn, max_tokens, error...
    input_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
