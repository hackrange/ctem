"""Tie a sign-in name (ACME\\jdoe, jdoe@acme.example, sulocal_jdoe) to a directory user."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def bare(name: str | None) -> str:
    """ACME\\jdoe and jdoe@ad.acme.example both become jdoe."""
    name = (name or "").strip()
    name = name.split("\\")[-1]
    return name.split("@", 1)[0].strip().lower()


class UserIndex:
    """Username -> user id, loaded once per batch so a sync doesn't query per device."""

    def __init__(self, ids: dict[str, str], prefixes: tuple[str, ...]):
        self.ids, self.prefixes = ids, prefixes

    @classmethod
    async def load(cls, db: AsyncSession) -> UserIndex:
        from api.core.config import get_settings
        from api.models.user import User

        rows = (await db.execute(select(User.username, User.id).where(User.is_local.is_(False)))).all()
        prefixes = tuple(p.strip().lower() for p in get_settings().account_alias_prefixes.split(",") if p.strip())
        return cls({u.lower(): i for u, i in rows if u}, prefixes)

    def resolve(self, name: str | None) -> tuple[str | None, bool]:
        """(user id, matched through an admin-style alias)."""
        b = bare(name)
        if not b:
            return None, False
        if b in self.ids:
            return self.ids[b], False
        for p in self.prefixes:
            if b.startswith(p) and b[len(p):] in self.ids:
                return self.ids[b[len(p):]], True
        return None, False
