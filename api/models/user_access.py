"""Per-user data access: "this person sees assets whose <tag role> is one of these values" (or an exact tag)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class UserAccessRule(Base):
    """One value of one rule. A user's rules are OR'd: any match grants the asset (and its findings).
    role_key: a tag role key from Admin > Tag mapping (executive_owner, application, ...), or "tag" for one exact tag."""
    __tablename__ = "user_access_rules"
    __table_args__ = (UniqueConstraint("user_id", "role_key", "value", name="uq_user_access_rule"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_key: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(String(256), nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), server_default=func.now())
