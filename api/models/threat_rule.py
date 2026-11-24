"""Threat Curated Rules: generic, reusable detections, learned from the AI's high-fidelity findings or written by hand
(api/hunt/curated.py). Hunts run these first, for free, and only pay the AI for what they don't already explain."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class ThreatRule(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "threat_rules"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)                # alert | splunk
    match: Mapped[dict] = mapped_column(JSON, nullable=False)                    # validated, generic: no hosts, users or IPs
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="high")
    description: Mapped[str | None] = mapped_column(Text)                        # why it matters
    what_to_do: Mapped[list | None] = mapped_column(JSON)
    attack: Mapped[list | None] = mapped_column(JSON)                            # MITRE ATT&CK ids
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="learned")   # learned | reviewed | manual
    learned_from: Mapped[str | None] = mapped_column(String(500))                # the question the AI was answering
    hits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(128))
    updated_by: Mapped[str | None] = mapped_column(String(128))
