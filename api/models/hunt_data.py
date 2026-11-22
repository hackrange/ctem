"""Threat hunting data: fleet stacks from endpoint telemetry, threat intel indicators, and EDR stream events.

A stack is one distinct thing seen on one day (a process by file and hash, a domain looked up, a remote address
and port, a logon) with the hosts that did it (up to HOSTS_CAP listed, the count kept). Raw telemetry stays in the
customer's own storage (Falcon Data Replicator's S3); CTEM keeps what hunting needs, for a set number of days."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, BigInteger, Boolean, Date, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, UUIDPrimaryKey

HOSTS_CAP = 200


class HuntStack(Base, UUIDPrimaryKey):
    __tablename__ = "hunt_stacks"
    __table_args__ = (UniqueConstraint("day", "kind", "key", name="uq_hunt_stack"),)

    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)            # process, dns, network, logon, logon_failed
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # hash of what identifies it
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)   # what a hunter searches: file, domain, ip:port, user
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    fields: Mapped[dict | None] = mapped_column(JSON)                         # a sample: command line, parent, user, protocol
    hosts: Mapped[list | None] = mapped_column(JSON)                          # EDR host ids, up to HOSTS_CAP
    host_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    intel_hit: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


class IntelIndicator(Base, UUIDPrimaryKey):
    __tablename__ = "intel_indicators"
    __table_args__ = (UniqueConstraint("source", "type", "value", name="uq_intel_indicator"),)

    source: Mapped[str] = mapped_column(String(32), nullable=False)           # crowdstrike
    type: Mapped[str] = mapped_column(String(32), nullable=False)             # domain, ip_address, hash_sha256, url...
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    confidence: Mapped[str | None] = mapped_column(String(16))
    actors: Mapped[list | None] = mapped_column(JSON)
    malware: Mapped[list | None] = mapped_column(JSON)
    labels: Mapped[list | None] = mapped_column(JSON)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class EdrEvent(Base, UUIDPrimaryKey):
    """An event from the EDR's real-time stream (detections, response sessions, console and API activity)."""
    __tablename__ = "edr_events"
    __table_args__ = (UniqueConstraint("source", "partition", "offset", name="uq_edr_event"),)

    source: Mapped[str] = mapped_column(String(32), nullable=False)
    partition: Mapped[str] = mapped_column(String(16), nullable=False)
    offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(253), index=True)
    user: Mapped[str | None] = mapped_column(String(256))
    summary: Mapped[str | None] = mapped_column(String(500))
    severity: Mapped[str | None] = mapped_column(String(16))
    event: Mapped[dict | None] = mapped_column(JSON)
