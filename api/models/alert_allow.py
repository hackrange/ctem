"""Accepted alerts (the allow list): a detection people have looked at and accepted, so it stops raising hunt findings,
hourly-check findings and Splunk feed alerts. Narrowed by host, process, parent process, file or hash; always with a reason and an
end date (api/core/alert_allow.py)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class AlertAllow(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "alert_allows"

    source: Mapped[str | None] = mapped_column(String(32))                    # crowdstrike, sentinelone ... (None: any)
    title: Mapped[str] = mapped_column(String(300), nullable=False, index=True)   # the detection, compared ignoring case
    hostname: Mapped[str | None] = mapped_column(String(253))                 # only on this host
    process: Mapped[str | None] = mapped_column(String(260))                  # only this process (file name)
    parent: Mapped[str | None] = mapped_column(String(260))                   # only when started by this process (file name)
    file: Mapped[str | None] = mapped_column(String(400))                     # only when the file it went after contains this
    sha256: Mapped[str | None] = mapped_column(String(64))                    # only this exact process hash
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    hits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
