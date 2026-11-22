"""High-fidelity alerts CTEM raises for a SIEM (Splunk HEC directly, or the shipper's local HEC / forwarder file)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class FeedAlert(Base):
    __tablename__ = "feed_alerts"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)   # delivery cursor
    key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)       # one alert per thing, once
    kind: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    event: Mapped[dict] = mapped_column(JSON, nullable=False)                        # what the SIEM receives
