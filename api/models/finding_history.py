"""History that outlives the findings it came from (api/core/finding_history.py).

FindingRollup: when a remediated finding is removed after the retention window, it is added here first, as one
count on the day it was found ("new") and one on the day it was fixed ("fixed", with its days to fix), by source,
kind of work, severity and KEV. The org-wide trend, fix counts and mean time to remediate keep their history.

DeviceDailyCount: each device's open, critical and high counts, written only on a day they change, so the device
trend line can reach back past the retention window. A day with no row carries the last row before it."""
from __future__ import annotations

from datetime import date

from sqlalchemy import Boolean, Date, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, UUIDPrimaryKey


class FindingRollup(Base, UUIDPrimaryKey):
    __tablename__ = "finding_rollups"
    __table_args__ = (UniqueConstraint("kind", "day", "source", "domain", "severity", "kev", name="uq_finding_rollup"),)

    kind: Mapped[str] = mapped_column(String(5), nullable=False)          # new | fixed
    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    domain: Mapped[str] = mapped_column(String(16), nullable=False, default="")   # infra, code, web, cloud or ""
    severity: Mapped[str] = mapped_column(String(8), nullable=False)      # critical, high, medium, low
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)        # "fixed" rows: how many had a found date
    fix_days: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)   # and the sum of their days to fix


class DeviceDailyCount(Base):
    __tablename__ = "device_daily_counts"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
