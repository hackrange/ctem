from __future__ import annotations

import enum
import uuid
from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.encryption import EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class FindingStatus(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    remediated = "remediated"
    risk_accepted = "risk_accepted"
    false_positive = "false_positive"


class Vulnerability(Base, UUIDPrimaryKey, TimestampMixin):
    """Normalized vulnerability definition (CVE or scanner-specific)."""
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)         # CVE-YYYY-NNNNN
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_base: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    epss_score: Mapped[float | None] = mapped_column(Float)                     # 0.0-1.0
    epss_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_added_date: Mapped[date | None] = mapped_column(Date)
    attack_vector: Mapped[str | None] = mapped_column(String(32))               # network, adjacent, local, physical
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exploit_maturity: Mapped[str | None] = mapped_column(String(32))            # poc, functional, weaponized
    source: Mapped[str] = mapped_column(String(64), nullable=False)             # qualys, rapid7, defender...
    source_vuln_id: Mapped[str | None] = mapped_column(String(256))
    # Devices with an open finding, refreshed by each scoring run (global view only)
    affected_devices: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False, index=True)

    findings: Mapped[list[Finding]] = relationship(back_populates="vuln")
    chains: Mapped[list[CVEChainMember]] = relationship(back_populates="vuln")


class Finding(Base, UUIDPrimaryKey, TimestampMixin):
    """A specific vulnerability instance on a specific device."""
    __tablename__ = "findings"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.open, nullable=False)
    first_detected: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Composite risk (recalculated by scoring engine)
    composite_score: Mapped[float | None] = mapped_column(Float)
    risk_grade: Mapped[str | None] = mapped_column(String(1))
    # What it would score with no containment discount, so the UI can show both
    raw_score: Mapped[float | None] = mapped_column(Float)
    raw_grade: Mapped[str | None] = mapped_column(String(1))

    # Reachability (populated by NodeZero or manual review)
    is_reachable: Mapped[bool | None] = mapped_column(Boolean)                  # None = not yet validated
    reachability_source: Mapped[str | None] = mapped_column(String(64))
    reachability_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    in_attack_chain: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Set while an approved exception covers this finding (status is then risk_accepted)
    exception_id: Mapped[str | None] = mapped_column(ForeignKey("vuln_exceptions.id", ondelete="SET NULL"), index=True)

    device: Mapped[object] = relationship("Device", back_populates="findings")
    vuln: Mapped[Vulnerability] = relationship(back_populates="findings")


class TicketRef(Base, UUIDPrimaryKey, TimestampMixin):
    """
    Tracks tickets (ServiceNow incidents) created from findings.
    One finding can have multiple tickets over its lifecycle.
    """
    __tablename__ = "ticket_refs"

    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    ticket_number: Mapped[str] = mapped_column(String(64), nullable=False)       # INC0001234 or "pending"
    ticket_url: Mapped[str | None] = mapped_column(String(512))
    ticket_system: Mapped[str] = mapped_column(String(32), default="servicenow", nullable=False)
    method: Mapped[str] = mapped_column(String(16), default="api", nullable=False)  # api | email
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    finding: Mapped[Finding] = relationship()


class CVEChain(Base, UUIDPrimaryKey, TimestampMixin):
    """A detected chain of CVEs that together form an exploit path."""
    __tablename__ = "cve_chains"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    chain_score: Mapped[float] = mapped_column(Float, nullable=False)
    mitre_techniques: Mapped[str | None] = mapped_column(Text)                  # comma-separated T-codes
    confirmed_by_pentest: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    members: Mapped[list[CVEChainMember]] = relationship(back_populates="chain", cascade="all, delete-orphan")


class CVEChainMember(Base):
    __tablename__ = "cve_chain_members"

    chain_id: Mapped[str] = mapped_column(ForeignKey("cve_chains.id", ondelete="CASCADE"), primary_key=True)
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True)
    sequence: Mapped[int] = mapped_column(nullable=False)                       # order in the chain

    chain: Mapped[CVEChain] = relationship(back_populates="members")
    vuln: Mapped[Vulnerability] = relationship(back_populates="chains")


class ExceptionStatus(str, enum.Enum):
    pending = "pending"        # an IT user asked; waiting for admin or cyber
    approved = "approved"      # in effect until expires_at
    rejected = "rejected"
    revoked = "revoked"        # ended early by admin or cyber
    expired = "expired"
    cancelled = "cancelled"    # withdrawn by the requester before a decision


class ExceptionScope(str, enum.Enum):
    finding = "finding"        # one vulnerability on one device
    devices = "devices"        # one vulnerability on chosen devices
    all = "all"                # one vulnerability everywhere, including devices found later
    tag = "tag"                # one vulnerability on every device with a tag, including ones tagged later


class VulnException(Base, UUIDPrimaryKey, TimestampMixin):
    """A time-boxed exception for a vulnerability. While approved, matching findings are risk_accepted,
    so they don't count toward risk, open counts, SLA or the GRC checks."""
    __tablename__ = "vuln_exceptions"

    vuln_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    scope: Mapped[ExceptionScope] = mapped_column(Enum(ExceptionScope), nullable=False)
    device_ids: Mapped[list | None] = mapped_column(JSON)            # finding / devices scopes
    tag_id: Mapped[str | None] = mapped_column(ForeignKey("tags.id", ondelete="SET NULL"))
    reason: Mapped[str] = mapped_column(EncryptedString, nullable=False)
    compensating_controls: Mapped[str | None] = mapped_column(EncryptedString)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    status: Mapped[ExceptionStatus] = mapped_column(Enum(ExceptionStatus), nullable=False, index=True)
    requested_by_id: Mapped[str | None] = mapped_column(String(36), index=True)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(EncryptedString)
    findings_covered: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    vuln: Mapped[Vulnerability] = relationship()
