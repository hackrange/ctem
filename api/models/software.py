"""Software inventory: normalized titles (one per product) and the installs (asset, version, source) under them."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.core.encryption import EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class SoftwareTitle(Base, UUIDPrimaryKey, TimestampMixin):
    """One product, whatever its versions (api/core/software_norm.py). Approved or unauthorized as a whole."""
    __tablename__ = "software_titles"

    key: Mapped[str] = mapped_column(String(300), nullable=False, unique=True, index=True)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    title: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)   # OS, updates, runtimes
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unreviewed", index=True)   # unreviewed | approved | unauthorized
    status_note: Mapped[str | None] = mapped_column(EncryptedString)
    decided_by: Mapped[str | None] = mapped_column(String(128))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class SoftwareInstall(Base, UUIDPrimaryKey):
    """One version of a title on one asset, as one source reported it."""
    __tablename__ = "software_installs"
    __table_args__ = (UniqueConstraint("title_id", "device_id", "version", "source", name="uq_software_install"),)

    title_id: Mapped[str] = mapped_column(ForeignKey("software_titles.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    product: Mapped[str | None] = mapped_column(String(256))     # the name as the source reported it
    # File details when the source has them (an EDR or privilege manager such as CyberArk EPM; scanners usually don't)
    publisher: Mapped[str | None] = mapped_column(String(256))   # the code-signing publisher
    install_path: Mapped[str | None] = mapped_column(String(512))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    md5: Mapped[str | None] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class SoftwareException(Base, UUIDPrimaryKey, TimestampMixin):
    """A title's decision for one asset that differs from the title's own: allowed here although unauthorized
    elsewhere, or not allowed here although approved. Until expires_at (None: no end). Audited."""
    __tablename__ = "software_exceptions"
    __table_args__ = (UniqueConstraint("title_id", "device_id", name="uq_software_exception"),)

    title_id: Mapped[str] = mapped_column(ForeignKey("software_titles.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)        # allowed | denied
    reason: Mapped[str] = mapped_column(EncryptedString, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[str] = mapped_column(String(128), nullable=False)
