"""GRC data mirrored from FairTPRM, plus CTEM's own control-check history."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.core.encryption import EncryptedJSON, EncryptedString
from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class _Mirrored:
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="fairtprm")
    external_id: Mapped[str] = mapped_column(String(64), nullable=False)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class GrcFramework(_Mirrored, Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "grc_frameworks"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_grc_frameworks_ext"),)

    code: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(50))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    compliance_year: Mapped[int | None] = mapped_column(Integer)
    total_requirements: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    implemented: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    partial: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    in_progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    planned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    not_applicable: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    compliance_percentage: Mapped[float | None] = mapped_column(Float)


class GrcControl(_Mirrored, Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "grc_controls"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_grc_controls_ext"),)

    control_ref: Mapped[str | None] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    control_type: Mapped[str | None] = mapped_column(String(32))
    control_category: Mapped[str | None] = mapped_column(String(32))
    implementation_status: Mapped[str | None] = mapped_column(String(32))
    effectiveness: Mapped[str | None] = mapped_column(String(32))
    risk_level: Mapped[str | None] = mapped_column(String(16))
    frequency: Mapped[str | None] = mapped_column(String(16))
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    mapped_requirements: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    frameworks: Mapped[list | None] = mapped_column(JSON)          # framework codes, e.g. ["ISO27001", "SOC2"]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class GrcRisk(_Mirrored, Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "grc_risks"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_grc_risks_ext"),)

    risk_ref: Mapped[str | None] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(EncryptedString)   # business detail; encrypted at rest
    risk_category: Mapped[str | None] = mapped_column(String(32))
    likelihood: Mapped[str | None] = mapped_column(String(32))
    impact: Mapped[str | None] = mapped_column(String(32))
    inherent_risk_score: Mapped[float | None] = mapped_column(Float)
    residual_risk_score: Mapped[float | None] = mapped_column(Float)
    risk_treatment: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str | None] = mapped_column(String(16))
    control_ids: Mapped[list | None] = mapped_column(JSON)         # FairTPRM control ids as strings
    vendor_id: Mapped[str | None] = mapped_column(String(64))      # FairTPRM vendor id (ThirdPartyRisk.external_id)
    review_date: Mapped[date | None] = mapped_column(Date)
    treatment_plan: Mapped[str | None] = mapped_column(EncryptedString)


class GrcEvidence(_Mirrored, Base, UUIDPrimaryKey, TimestampMixin):
    """Evidence metadata only; the files stay in FairTPRM."""
    __tablename__ = "grc_evidence"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_grc_evidence_ext"),)

    evidence_ref: Mapped[str | None] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_type: Mapped[str | None] = mapped_column(String(32))
    collection_method: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str | None] = mapped_column(String(16))
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    control_ids: Mapped[list | None] = mapped_column(JSON)


class GrcMonitor(_Mirrored, Base, UUIDPrimaryKey, TimestampMixin):
    """A FairTPRM continuous monitor; the ones backed by CTEM carry a ctem_* check_type."""
    __tablename__ = "grc_monitors"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_grc_monitors_ext"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    check_type: Mapped[str | None] = mapped_column(String(100), index=True)
    collector_class: Mapped[str | None] = mapped_column(String(255))
    frequency: Mapped[str | None] = mapped_column(String(16))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_result: Mapped[str | None] = mapped_column(String(16))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    control_ids: Mapped[list | None] = mapped_column(JSON)


class GrcAssessment(_Mirrored, Base, UUIDPrimaryKey, TimestampMixin):
    """A FairTPRM maturity assessment: scores and counts. Gaps say where we're weak, so they're encrypted."""
    __tablename__ = "grc_assessments"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_grc_assessments_ext"),)

    assessment_ref: Mapped[str | None] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    assessment_type: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str | None] = mapped_column(String(32))
    planned_start: Mapped[date | None] = mapped_column(Date)
    planned_end: Mapped[date | None] = mapped_column(Date)
    actual_start: Mapped[date | None] = mapped_column(Date)
    actual_end: Mapped[date | None] = mapped_column(Date)
    fairscore: Mapped[float | None] = mapped_column(Float)            # 1.00 - 4.00
    compliance_pct: Mapped[float | None] = mapped_column(Float)
    progress: Mapped[dict | None] = mapped_column(JSON)
    domain_scores: Mapped[list | None] = mapped_column(JSON)
    framework_compliance: Mapped[list | None] = mapped_column(JSON)
    gaps: Mapped[list | None] = mapped_column(EncryptedJSON)
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class GrcAudit(_Mirrored, Base, UUIDPrimaryKey, TimestampMixin):
    """A FairTPRM audit and its findings (titles, severity, status; no remediation text)."""
    __tablename__ = "grc_audits"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_grc_audits_ext"),)

    audit_ref: Mapped[str | None] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    audit_type: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str | None] = mapped_column(String(32))
    framework_code: Mapped[str | None] = mapped_column(String(50))
    audit_firm: Mapped[str | None] = mapped_column(String(255))
    planned_start: Mapped[date | None] = mapped_column(Date)
    planned_end: Mapped[date | None] = mapped_column(Date)
    actual_end: Mapped[date | None] = mapped_column(Date)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    certification_valid_until: Mapped[date | None] = mapped_column(Date)
    findings: Mapped[list | None] = mapped_column(EncryptedJSON)


class GrcCheckResult(Base, UUIDPrimaryKey):
    """One run of a CTEM control check. Kept 400 days so a full audit year has history."""
    __tablename__ = "grc_check_results"

    check_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    check_version: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict | None] = mapped_column(EncryptedJSON)
    thresholds: Mapped[dict | None] = mapped_column(JSON)
    data_freshness: Mapped[dict | None] = mapped_column(JSON)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
