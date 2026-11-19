from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.encryption import EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class DeviceType(str, enum.Enum):
    workstation = "workstation"
    server = "server"
    network_device = "network_device"
    cloud_instance = "cloud_instance"
    unknown = "unknown"


class RiskGrade(str, enum.Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class Device(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "devices"

    hostname: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    fqdn: Mapped[str | None] = mapped_column(String(512))
    ip: Mapped[str | None] = mapped_column(EncryptedString)
    ip_hash: Mapped[str | None] = mapped_column(String(64), index=True)  # HMAC for search
    mac_address: Mapped[str | None] = mapped_column(String(17))
    os: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(128))
    device_type: Mapped[DeviceType] = mapped_column(Enum(DeviceType), default=DeviceType.unknown, nullable=False)

    # Active Directory
    ad_dn: Mapped[str | None] = mapped_column(EncryptedString)
    ad_joined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ad_last_logon: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Last activity
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_login_user: Mapped[str | None] = mapped_column(EncryptedString)
    last_login_user_hash: Mapped[str | None] = mapped_column(String(64), index=True)

    # Endpoint protection
    edr_vendor: Mapped[str | None] = mapped_column(String(64))  # crowdstrike, sentinelone, defender, none
    edr_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    edr_last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Network exposure
    is_internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Risk
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_grade: Mapped[RiskGrade | None] = mapped_column(Enum(RiskGrade))

    # Source tracking
    source: Mapped[str | None] = mapped_column(String(64))  # ldap, qualys, crowdstrike...
    source_id: Mapped[str | None] = mapped_column(String(256))

    # Owner
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    tags: Mapped[list[DeviceTag]] = relationship(back_populates="device", cascade="all, delete-orphan")
    findings: Mapped[list] = relationship("Finding", back_populates="device")
    owner: Mapped[object | None] = relationship("User", foreign_keys=[owner_user_id])


class DeviceTag(Base):
    __tablename__ = "device_tags"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    tag_id: Mapped[str] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)

    device: Mapped[Device] = relationship(back_populates="tags")
    tag: Mapped[object] = relationship("Tag")
