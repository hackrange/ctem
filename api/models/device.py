from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.device_match import NOT_HOSTS, add_source, host_key
from api.core.encryption import EncryptedJSON, EncryptedString
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
    host_key: Mapped[str | None] = mapped_column(String(253), index=True)  # see api.core.device_match
    ip: Mapped[str | None] = mapped_column(EncryptedString)
    ip_hash: Mapped[str | None] = mapped_column(String(64), index=True)  # HMAC for search
    mac_address: Mapped[str | None] = mapped_column(String(17))
    os: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(128))
    device_type: Mapped[DeviceType] = mapped_column(Enum(DeviceType), default=DeviceType.unknown, nullable=False)

    # Active Directory
    ad_dn: Mapped[str | None] = mapped_column(EncryptedString)
    ad_ou_keys: Mapped[str | None] = mapped_column(Text)   # keyed hashes of the DN's OU names (api.core.device_ou)
    ad_joined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ad_last_logon: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Last activity
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_login_user: Mapped[str | None] = mapped_column(EncryptedString)
    last_login_user_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    recent_logins: Mapped[list | None] = mapped_column(EncryptedJSON)   # newest first, from the EDR's login history

    # Endpoint protection
    edr_vendor: Mapped[str | None] = mapped_column(String(64))  # crowdstrike, sentinelone, defender, none
    edr_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    edr_last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    edr_contained: Mapped[bool | None] = mapped_column(Boolean)  # network-isolated by the EDR
    edr_hidden: Mapped[bool | None] = mapped_column(Boolean)     # hidden in the EDR console (Falcon "hide host")
    edr_device_id: Mapped[str | None] = mapped_column(String(64))  # the EDR's own host id (Falcon aid)
    raw_risk_score: Mapped[float | None] = mapped_column(Float)  # score before the containment discount
    raw_risk_grade: Mapped[str | None] = mapped_column(String(1))
    # From the EDR's policies; None means the feed couldn't tell us
    firewall_enabled: Mapped[bool | None] = mapped_column(Boolean)
    usb_storage_blocked: Mapped[bool | None] = mapped_column(Boolean)

    # Network exposure
    is_internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Risk
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_grade: Mapped[RiskGrade | None] = mapped_column(Enum(RiskGrade))
    # Rolled up by the scoring engine so lists can sort on them cheaply
    open_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    kev_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    # Not In Scope: set by admin or cyber with a justification and an end date. While it runs, nothing on
    # the device counts against it (risk 0, no open findings, left out of vuln counts and GRC checks).
    scope_exempt_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    scope_exempt_reason: Mapped[str | None] = mapped_column(EncryptedString)
    scope_exempt_by: Mapped[str | None] = mapped_column(String(128))
    scope_exempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Business criticality from the scanner (Rapid7: Very High ... Very Low); weights risk scoring
    criticality: Mapped[str | None] = mapped_column(String(16))

    # Source tracking
    source: Mapped[str | None] = mapped_column(String(64))  # ldap, qualys, crowdstrike...
    source_id: Mapped[str | None] = mapped_column(String(256))
    sources: Mapped[str | None] = mapped_column(String(512))  # every feed that saw it: ",crowdstrike,ldap,"

    # Owner
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    tags: Mapped[list[DeviceTag]] = relationship(back_populates="device", cascade="all, delete-orphan")
    findings: Mapped[list] = relationship("Finding", back_populates="device")
    owner: Mapped[object | None] = relationship("User", foreign_keys=[owner_user_id])  # detected from sign-ins
    assignment: Mapped[DeviceAssignment | None] = relationship(back_populates="device", uselist=False,
                                                               cascade="all, delete-orphan")


@event.listens_for(Device, "before_insert")
@event.listens_for(Device, "before_update")
def _set_host_key(_mapper, _conn, dev: Device) -> None:
    dev.host_key = None if dev.source in NOT_HOSTS else host_key(dev.hostname)
    add_source(dev, dev.source)


class DeviceAssignment(Base, UUIDPrimaryKey, TimestampMixin):
    """Who is supposed to use a device, and where it is. Set by people (admin/inventory), never by a sync."""
    __tablename__ = "device_assignments"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, unique=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    assigned_by: Mapped[str | None] = mapped_column(String(128))
    note: Mapped[str | None] = mapped_column(EncryptedString)
    # shipped | lost | stolen | returned; None = in normal use
    status: Mapped[str | None] = mapped_column(String(16), index=True)
    status_by: Mapped[str | None] = mapped_column(String(128))
    status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status_note: Mapped[str | None] = mapped_column(EncryptedString)
    carrier: Mapped[str | None] = mapped_column(String(8))           # ups | fedex | usps | dhl, only while shipped
    tracking_number: Mapped[str | None] = mapped_column(String(40))

    device: Mapped[Device] = relationship(back_populates="assignment")
    user: Mapped[object] = relationship("User", foreign_keys=[user_id])


class DeviceTag(Base):
    __tablename__ = "device_tags"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    tag_id: Mapped[str] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)

    device: Mapped[Device] = relationship(back_populates="tags")
    tag: Mapped[object] = relationship("Tag")
