"""Tag roles: what a customer's tags mean to CTEM (executive owner, application, environment...).

Each role has match rules over tag names ("starts with" or "is exactly", case-insensitive). Mapping never
changes stored tags; it only changes how CTEM reads them."""
from __future__ import annotations

from sqlalchemy import JSON, Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey


class TagRole(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "tag_roles"

    key: Mapped[str] = mapped_column(String(40), unique=True, nullable=False, index=True)   # executive_owner, custom_x
    name: Mapped[str] = mapped_column(String(60), nullable=False)                          # shown in the UI
    builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)          # CTEM features read these
    show_filter: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)       # a dashboard dropdown
    title_case: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)       # "jeff davis" -> "Jeff Davis"
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rules: Mapped[list] = mapped_column(JSON, default=list, nullable=False)                # [{"match": "prefix", "value": "owner:E-O:"}]
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(255))
