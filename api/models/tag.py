from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, TimestampMixin, UUIDPrimaryKey
import uuid


class Tag(Base, UUIDPrimaryKey, TimestampMixin):
    """Normalized asset tag. Pulled from LDAP OUs, Qualys groups, CrowdStrike, or created manually."""
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("name", name="uq_tag_name"),)

    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)             # ldap, qualys, crowdstrike, manual...
    source_id: Mapped[str | None] = mapped_column(String(256))                  # ID in the source system
    description: Mapped[str | None] = mapped_column(Text)

    group_access: Mapped[list[GroupTagAccess]] = relationship(back_populates="tag", cascade="all, delete-orphan")


class GroupTagAccess(Base):
    """
    Grants members of a role or AD group access to assets tagged with this tag.
    Example: role 'it_user' + tag 'dept:finance' -> IT users can see finance machines.
    """
    __tablename__ = "group_tag_access"

    role_name: Mapped[str] = mapped_column(String(64), primary_key=True)        # role name or AD group CN
    tag_id: Mapped[str] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)

    tag: Mapped[Tag] = relationship(back_populates="group_access")
