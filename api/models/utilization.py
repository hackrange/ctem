"""Server utilization history: one row a minute (kept 2 days) and one an hour (kept 400 days)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class UtilSample(Base):
    __tablename__ = "util_samples"

    tier: Mapped[str] = mapped_column(String(1), primary_key=True)                  # "m" minute, "h" hour
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    host_cpu: Mapped[float | None] = mapped_column(Float)                           # % of every core
    host_cpu_max: Mapped[float | None] = mapped_column(Float)
    mem_used: Mapped[int | None] = mapped_column(BigInteger)
    mem_total: Mapped[int | None] = mapped_column(BigInteger)
    disk_used: Mapped[int | None] = mapped_column(BigInteger)
    disk_total: Mapped[int | None] = mapped_column(BigInteger)
    db_bytes: Mapped[int | None] = mapped_column(BigInteger)                        # CTEM's own database
    redis_bytes: Mapped[int | None] = mapped_column(BigInteger)
