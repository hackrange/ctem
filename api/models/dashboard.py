"""Dashboards people build from the widget catalog, and Favorites (starred dashboards; other pages later)."""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class Visibility(str, enum.Enum):
    private = "private"      # the owner (and admins, who can see every dashboard)
    roles = "roles"          # people with any of share_roles
    everyone = "everyone"    # every signed-in person


class Dashboard(Base, UUIDPrimaryKey, TimestampMixin):
    """A grid of widgets. Widgets hold a metric id, a chart type and allow-listed parameters, never queries;
    each viewer's numbers are computed for what that viewer may see."""
    __tablename__ = "dashboards"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    owner_name: Mapped[str] = mapped_column(String(255), nullable=False)
    visibility: Mapped[Visibility] = mapped_column(Enum(Visibility), nullable=False, default=Visibility.private)
    share_roles: Mapped[list | None] = mapped_column(JSON)
    widgets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class Favorite(Base, UUIDPrimaryKey):
    """Something a person starred. kind is allow-listed; ref is the thing's id."""
    __tablename__ = "favorites"
    __table_args__ = (UniqueConstraint("user_id", "kind", "ref", name="uq_favorite"),)

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    ref: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
