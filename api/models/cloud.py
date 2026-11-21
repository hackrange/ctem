"""Cloud instances and their network exposure, from AWS, Azure and OCI (api/cloud/).

One row per instance per integration: its private and public addresses and every inbound port its cloud
firewalls (security groups, NSGs, security lists) open, with who may reach it. The matching CTEM device gets
is_internet_exposed from these facts, and scoring reads the ports per finding."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class CloudAsset(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "cloud_assets"
    __table_args__ = (UniqueConstraint("provider", "resource_id", name="uq_cloud_asset"),)

    integration_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)          # aws, azure, oci
    account: Mapped[str | None] = mapped_column(String(128))                   # account id, subscription, tenancy
    region: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)      # i-..., VM resource id, OCID
    name: Mapped[str | None] = mapped_column(String(255))
    private_ips: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    public_ips: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    # [{"proto": "tcp", "from": 443, "to": 443, "reach": "internet"|"any_internal"|"restricted",
    #   "sources": ["0.0.0.0/0"], "via": "sg-0abc (web)"}]
    ports: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
