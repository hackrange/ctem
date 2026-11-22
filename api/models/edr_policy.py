"""EDR policies as the EDR reported them: prevention settings, firewall rulesets and device control (USB).

Hosts point at theirs (Device.edr_prevention_policy, edr_firewall_policy, edr_usb_policy). One row per policy, so
thousands of hosts sharing a policy store it once."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class EdrPolicy(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "edr_policies"
    __table_args__ = (UniqueConstraint("vendor", "policy_id", "kind", name="uq_edr_policy"),)

    vendor: Mapped[str] = mapped_column(String(64), nullable=False)        # crowdstrike
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)          # prevention, firewall, device_control
    name: Mapped[str | None] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    platform: Mapped[str | None] = mapped_column(String(32))
    body: Mapped[dict | None] = mapped_column(JSON)                         # settings, ruleset or device classes
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
