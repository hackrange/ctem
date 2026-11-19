from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

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
