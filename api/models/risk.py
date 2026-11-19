from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.encryption import EncryptedJSON
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class RiskScore(Base, UUIDPrimaryKey, TimestampMixin):
    """Current risk score for a user or device."""
    __tablename__ = "risk_scores"

    entity_type: Mapped[str] = mapped_column(String(16), nullable=False)        # user | device
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(1), nullable=False)
    score_breakdown: Mapped[str | None] = mapped_column(String(1024))           # JSON snapshot of contributing factors
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RiskScoreHistory(Base):
    """
    TimescaleDB hypertable for risk score trends.
    Partitioned by time -- don't add a standard UUID PK here.
    """
    __tablename__ = "risk_score_history"

    entity_type: Mapped[str] = mapped_column(String(16), primary_key=True)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(1), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)


class AttackPath(Base, UUIDPrimaryKey, TimestampMixin):
    """NodeZero-confirmed or detected attack path from entry point to target."""
    __tablename__ = "attack_paths"

    source_device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    target_device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    path_description: Mapped[str | None] = mapped_column(String(2048))
    impact_description: Mapped[str | None] = mapped_column(String(1024))
    path_score: Mapped[float] = mapped_column(Float, nullable=False)
    confirmed_by: Mapped[str | None] = mapped_column(String(64))                # horizon3, manual
    external_id: Mapped[str | None] = mapped_column(String(256))                # NodeZero path ID
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    source_device: Mapped[object | None] = relationship("Device", foreign_keys=[source_device_id])
    target_device: Mapped[object | None] = relationship("Device", foreign_keys=[target_device_id])


class ThirdPartyRisk(Base, UUIDPrimaryKey, TimestampMixin):
    """
    Third-party / supplier risk record from FairTPRM or similar TPRM platform.
    Keyed by (source, external_id) -- suppliers don't live in our device/user tables.
    """
    __tablename__ = "third_party_risks"

    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)      # fairtprm, manual
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True) # supplier ID in source system
    supplier_name: Mapped[str] = mapped_column(String(256), nullable=False)
    tier: Mapped[str | None] = mapped_column(String(32))                              # tier1, tier2, tier3
    status: Mapped[str | None] = mapped_column(String(32))                            # active, offboarded, reviewing
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_grade: Mapped[str] = mapped_column(String(1), default="A", nullable=False)
    open_gaps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_assessment: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_review: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extra: Mapped[dict | None] = mapped_column(EncryptedJSON)                        # arbitrary source metadata


class ThirdPartyControlGap(Base, UUIDPrimaryKey, TimestampMixin):
    """
    A specific control gap from a third-party assessment.
    Child of ThirdPartyRisk -- one supplier can have many gaps.
    """
    __tablename__ = "third_party_control_gaps"

    supplier_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("third_party_risks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True) # control gap ID in source
    control_name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    supplier: Mapped[ThirdPartyRisk] = relationship(back_populates="gaps")


ThirdPartyRisk.gaps = relationship(  # type: ignore[attr-defined]
    ThirdPartyControlGap, back_populates="supplier", cascade="all, delete-orphan"
)


class RiskException(Base, UUIDPrimaryKey, TimestampMixin):
    """
    Approved risk exception -- temporarily accepts a finding's risk
    without remediation. Approval gated by cyber/admin role.
    Expires automatically; compliance reports treat expired as unapproved.
    """
    __tablename__ = "risk_exceptions"

    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    cve_id: Mapped[str | None] = mapped_column(String(32))          # direct CVE ref if no finding FK
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(128), nullable=False)  # username, not user_id
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_permanent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
