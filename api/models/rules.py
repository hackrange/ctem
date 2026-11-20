"""Curated rules written by admins (the JSON standard lives in api/rules/doc.py)."""
from __future__ import annotations

from sqlalchemy import JSON, Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class CuratedRule(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "curated_rules"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    check_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)       # validated RuleDoc.dump()
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(128))
    updated_by: Mapped[str | None] = mapped_column(String(128))
