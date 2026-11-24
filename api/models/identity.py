"""Identity risk models -- ITDR alerts, SaaS/AI app records, per-identity risk."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey
from api.core.encryption import EncryptedJSON


class ItdrThreatType(str, enum.Enum):
    credential_compromise = "credential_compromise"
    impossible_travel = "impossible_travel"
    mfa_bypass = "mfa_bypass"
    mfa_fatigue = "mfa_fatigue"
    account_takeover = "account_takeover"
    privilege_escalation = "privilege_escalation"
    oauth_abuse = "oauth_abuse"
    data_exfiltration = "data_exfiltration"
    brute_force = "brute_force"
    session_hijack = "session_hijack"
    risky_oauth_grant = "risky_oauth_grant"
    anomalous_access = "anomalous_access"
    unknown = "unknown"


class ItdrAlertStatus(str, enum.Enum):
    active = "active"
    resolved = "resolved"
    false_positive = "false_positive"
    investigating = "investigating"


class IdentityThreat(Base, UUIDPrimaryKey, TimestampMixin):
    """
    ITDR alert from Grip Security (or any identity threat source).
    Stored separately from vuln findings -- identity threats are user-centric,
    not CVE-centric.
    """
    __tablename__ = "identity_threats"

    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)   # grip, crowdstrike_id, etc.
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    threat_type: Mapped[ItdrThreatType] = mapped_column(
        Enum(ItdrThreatType), default=ItdrThreatType.unknown, nullable=False, index=True
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # critical/high/medium/low
    status: Mapped[ItdrAlertStatus] = mapped_column(
        Enum(ItdrAlertStatus), default=ItdrAlertStatus.active, nullable=False, index=True
    )

    # Identity reference -- store hash only, never plain email
    user_email_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    user_display: Mapped[str | None] = mapped_column(String(256))               # username or partial email (last 2 chars @ domain)
    user_external_id: Mapped[str | None] = mapped_column(String(256))           # Grip user UUID

    # App context
    app_name: Mapped[str | None] = mapped_column(String(256))
    app_external_id: Mapped[str | None] = mapped_column(String(256))

    # Event details
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32))          # T1078, T1110, etc.
    source_ip: Mapped[str | None] = mapped_column(String(45))
    country: Mapped[str | None] = mapped_column(String(64))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Raw payload for drilldown
    raw: Mapped[dict | None] = mapped_column(EncryptedJSON)


class SaasAppRecord(Base, UUIDPrimaryKey, TimestampMixin):
    """
    SaaS or AI app discovered via Grip Security (or similar SaaS discovery tool).
    shadow_ai=True means it's an AI tool (ChatGPT, Copilot, etc.) not on the sanctioned list.
    """
    __tablename__ = "saas_app_records"

    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    app_name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    app_category: Mapped[str | None] = mapped_column(String(64), index=True)    # ai, collaboration, dev, storage...
    vendor: Mapped[str | None] = mapped_column(String(256))
    is_shadow_ai: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    is_sanctioned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    risk_score: Mapped[float | None] = mapped_column(Float)
    user_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    data_access_scopes: Mapped[list | None] = mapped_column(EncryptedJSON)
    oauth_scopes: Mapped[list | None] = mapped_column(EncryptedJSON)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IdentityRiskScore(Base, UUIDPrimaryKey, TimestampMixin):
    """
    Aggregate identity risk per unique identity (email_hash key).
    Rolled up from ITDR alerts + posture findings + shadow app usage.
    Fed into the composite scoring engine for device/user risk.
    """
    __tablename__ = "identity_risk_scores"

    user_email_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    user_display: Mapped[str | None] = mapped_column(String(256))

    # Component scores (0-100)
    itdr_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    posture_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    shadow_saas_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    shadow_ai_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    composite_identity_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    # Credentials and browser (Grip passwordPosture, mfaStatusByApp and extensions; api/integrations/grip_extras.py)
    credential_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    leaked_password_accounts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reused_password_accounts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    weak_password_accounts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risky_extensions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    mfa_coverage_pct: Mapped[int | None] = mapped_column(Integer)

    # Counts for quick display
    active_itdr_alerts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    posture_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    shadow_saas_apps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    shadow_ai_apps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    last_synced: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PostureFinding(Base, UUIDPrimaryKey, TimestampMixin):
    """
    Identity posture finding from Grip Security.
    Examples: MFA not enforced, excessive OAuth scopes, dormant admin accounts.
    """
    __tablename__ = "posture_findings"

    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # Scope -- may apply to a user, an app, or both
    user_email_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    user_display: Mapped[str | None] = mapped_column(String(256))
    app_name: Mapped[str | None] = mapped_column(String(256))
    app_external_id: Mapped[str | None] = mapped_column(String(256))

    affected_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
