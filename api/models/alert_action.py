"""Updates people make to an EDR alert from CTEM (close, reopen, comment, classify), sent to the EDR directly or by
the shipper that reads it (api/core/cs_alert_actions.py)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, UUIDPrimaryKey


class AlertAction(Base, UUIDPrimaryKey):
    __tablename__ = "alert_actions"

    alert_key: Mapped[str] = mapped_column(String(300), nullable=False, index=True)   # threat_alert_<composite id>
    composite_id: Mapped[str] = mapped_column(String(200), nullable=False)
    integration_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    via: Mapped[str] = mapped_column(String(16), nullable=False)                      # direct | shipper
    state: Mapped[str] = mapped_column(String(16), nullable=False, index=True)        # queued | sent | done | failed
    params: Mapped[dict] = mapped_column(JSON, nullable=False)                       # status, classification, comment
    requested_by: Mapped[str] = mapped_column(String(36), nullable=False)
    requested_by_name: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
