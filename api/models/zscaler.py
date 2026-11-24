"""Zscaler Client Connector devices as the last sync saw them, matched to CTEM's devices by host name
(api/integrations/zscaler_posture.py)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class ZscalerDevice(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "zscaler_devices"

    udid: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    host_key: Mapped[str | None] = mapped_column(String(253), index=True)
    hostname: Mapped[str | None] = mapped_column(String(253))
    device_id: Mapped[str | None] = mapped_column(String(36), index=True)   # CTEM's device, when the name matches one
    user: Mapped[str | None] = mapped_column(String(256))
    os_version: Mapped[str | None] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(64))
    registration_state: Mapped[str | None] = mapped_column(String(32), index=True)
    tunnel_status: Mapped[str | None] = mapped_column(String(64))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    zdx: Mapped[bool] = mapped_column(default=False, nullable=False)          # reports to ZDX (digital experience)
