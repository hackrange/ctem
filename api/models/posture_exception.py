"""An accepted EDR posture check (a Zero Trust Assessment check like a CPU mitigation): while it is in force, the check
shows as Excepted instead of failing, on one device, every device with a tag, every device of a type, or everywhere."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.core.encryption import EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey

SCOPES = ("device", "tag", "type", "all")


class PostureException(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "posture_exceptions"

    check: Mapped[str] = mapped_column(String(200), nullable=False, index=True)        # the check's name, as the EDR reports it
    scope: Mapped[str] = mapped_column(String(8), nullable=False)                       # device | tag | type | all
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    tag_id: Mapped[str | None] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), index=True)
    device_type: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(EncryptedString, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
