"""Daily values of counts that have no history of their own (stale AD objects by threshold), so dashboards
can draw a trend. One row per key per day; recording again the same day overwrites it."""
from __future__ import annotations

from datetime import date

from sqlalchemy import BigInteger, Date, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)      # "stale_computers_90"
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    value: Mapped[int] = mapped_column(BigInteger, nullable=False)
