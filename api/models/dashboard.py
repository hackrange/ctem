"""Dashboards people build from the widget catalog, and Favorites (starred dashboards; other pages later)."""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String, Text, UniqueConstraint, text
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
    widgets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)   # what viewers see once published
    theme: Mapped[str] = mapped_column(String(24), nullable=False, default="default", server_default=text("'default'"))
    # A new dashboard is a draft only its owner (and admins) see. Once published, edits are saved to `draft`
    # ({"widgets", "theme"}) and viewers keep seeing the published version until the owner publishes again.
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("true"))
    draft: Mapped[dict | None] = mapped_column(JSON)
    # Dashboard-wide conditions every widget honors: {"filters": [...], "match": "all"|"any"} (see dashboards.filters)
    filters: Mapped[dict | None] = mapped_column(JSON)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # viewer: every widget shows only what each viewer may see (the default). everything: the published widgets
    # show all the data to everyone it's shared with. Only admins and cyber can set it; it resets when anyone else
    # changes or publishes the dashboard (api/routes/dashboards.py).
    data_scope: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer", server_default=text("'viewer'"))
    # Someone who can't set "everything" asked for it: {"by", "at", "why"} until an admin or cyber approves or denies
    scope_request: Mapped[dict | None] = mapped_column(JSON)
    scope_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # "everything" ends then (None: no end)


class Favorite(Base, UUIDPrimaryKey):
    """Something a person starred. kind is allow-listed; ref is the thing's id."""
    __tablename__ = "favorites"
    __table_args__ = (UniqueConstraint("user_id", "kind", "ref", name="uq_favorite"),)

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    ref: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
