from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.core.encryption import EncryptedJSON
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class SyncStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    success = "success"
    failed = "failed"
    disabled = "disabled"


# All vendor slugs -- keeping them explicit prevents typos downstream
class Vendor(str, enum.Enum):
    qualys = "qualys"
    rapid7_insightvm = "rapid7_insightvm"
    rapid7_appsec = "rapid7_appsec"
    rapid7_cloudsec = "rapid7_cloudsec"
    horizon3 = "horizon3"
    grip = "grip"
    crowdstrike = "crowdstrike"
    sentinelone = "sentinelone"
    ldap = "ldap"
    guardicore = "guardicore"
    splunk = "splunk"
    msdefender = "msdefender"
    cortex_xdr = "cortex_xdr"
    paloalto_ngfw = "paloalto_ngfw"
    fortinet = "fortinet"
    tanium = "tanium"
    servicenow = "servicenow"
    snyk = "snyk"
    github_advanced = "github_advanced"
    forgerepo = "forgerepo"
    github_code_review = "github_code_review"   # GCR: SAST and DAST
    ai = "ai"
    anthropic = "anthropic"
    openai = "openai"
    custom_ai = "custom_ai"
    bedrock = "bedrock"
    zscaler = "zscaler"
    fairtprm = "fairtprm"
    netprobe = "netprobe"   # the shipper's network discovery (ping and common ports)
    email = "email"             # outgoing mail: SMTP or Microsoft 365 Graph (api/core/email.py)
    aws = "aws"                 # cloud exposure (api/cloud/)
    azure = "azure"
    oci = "oci"


class IntegrationConfig(Base, UUIDPrimaryKey, TimestampMixin):
    """
    One row per configured integration instance.
    Credentials live in config_encrypted (AES-256-GCM JSON blob).
    """
    __tablename__ = "integration_configs"

    vendor: Mapped[Vendor] = mapped_column(Enum(Vendor), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict | None] = mapped_column(EncryptedJSON("integration_configs.config"))   # all credentials + settings
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_status: Mapped[SyncStatus | None] = mapped_column(Enum(SyncStatus))
    last_sync_error: Mapped[str | None] = mapped_column(Text)
    sync_schedule: Mapped[str | None] = mapped_column(String(64))               # cron expression


class SyncJob(Base, UUIDPrimaryKey, TimestampMixin):
    """History of every integration sync run."""
    __tablename__ = "sync_jobs"

    integration_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    vendor: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[SyncStatus] = mapped_column(Enum(SyncStatus), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_imported: Mapped[int | None] = mapped_column()
    error_message: Mapped[str | None] = mapped_column(Text)
