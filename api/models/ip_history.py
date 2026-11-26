"""IP address usage history: which asset, and which person on it, held an address, and from when to when (GMT).

Addresses are short-lived (DHCP leases, home and carrier public addresses), so "who held this address last March?" needs
a record made at the time. Each row is one span: the same asset, address and person seen continuously; a change
starts a new span. Private (RFC 1918 and other internal ranges) and public addresses are both kept. The address is
encrypted like the device's own, with keyed hashes to find it exactly or by its /24 (IPv6: /64). Kept two years."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from api.core.encryption import EncryptedString
from api.models.base import Base, UUIDPrimaryKey


class IpSighting(UUIDPrimaryKey, Base):
    __tablename__ = "ip_sightings"

    ip: Mapped[str] = mapped_column(EncryptedString)
    ip_hash: Mapped[str] = mapped_column(String(64), index=True)
    net_hash: Mapped[str] = mapped_column(String(64), index=True)      # its /24 (IPv6 /64), for "anything in that range"
    kind: Mapped[str] = mapped_column(String(10))                       # private | public
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))           # as it was then (assets get renamed or retired)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    username: Mapped[str | None] = mapped_column(EncryptedString)      # who was on it then: the detected user or last sign-in
    sources: Mapped[str | None] = mapped_column(String(128))            # the tools that reported the address
    address_how: Mapped[str | None] = mapped_column(String(300))        # how the address was tied to the asset
    person_how: Mapped[str | None] = mapped_column(String(300))         # how the person was tied to the asset
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (Index("ix_ip_sightings_device_ip_last", "device_id", "ip_hash", "last_seen"),)
