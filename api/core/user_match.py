"""Tie a sign-in name (ACME\\jdoe, jdoe@acme.example, sulocal_jdoe) to a directory user."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def upn_keys(upn: str) -> tuple[str, str]:
    """(hash of the whole UPN, hash of its first half): jane.doe@acme.example finds them typed either way."""
    from api.core.encryption import search_hash
    u = upn.strip().lower()
    return search_hash(u), search_hash(u.split("@", 1)[0])


def set_upn(user, upn: str) -> None:
    user.upn = upn
    user.upn_hash, user.upn_local_hash = upn_keys(upn)


def bare(name: str | None) -> str:
    """ACME\\jdoe and jdoe@ad.acme.example both become jdoe."""
    name = (name or "").strip()
    name = name.split("\\")[-1]
    return name.split("@", 1)[0].strip().lower()


class UserIndex:
    """Username -> user id, loaded once per batch so a sync doesn't query per device."""

    def __init__(self, ids: dict[str, str], prefixes: tuple[str, ...], firsts: dict[str, str] | None = None,
                 upns: dict[str, str] | None = None):
        self.ids, self.prefixes, self.firsts, self.upns = ids, prefixes, firsts or {}, upns or {}

    @classmethod
    async def load(cls, db: AsyncSession) -> UserIndex:
        from api.core.config import get_settings
        from api.models.user import User

        rows = (await db.execute(select(User.username, User.id, User.first_name, User.display_name, User.is_active,
                                        User.ad_disabled, User.is_service_account, User.upn_hash).where(User.is_local.is_(False)))).all()
        prefixes = tuple(p.strip().lower() for p in get_settings().account_alias_prefixes.split(",") if p.strip())
        return cls({r.username.lower(): r.id for r in rows if r.username}, prefixes, _unique_first_names(rows),
                   {r.upn_hash: r.id for r in rows if r.upn_hash})

    def resolve(self, name: str | None) -> tuple[str | None, bool]:
        """(user id, matched through an admin-style alias)."""
        b = bare(name)
        if not b:
            return None, False
        if "@" in (name or "") and self.upns:  # mark.langston@ad.acme.example, by the user's real UPN
            from api.core.encryption import search_hash
            uid = self.upns.get(search_hash(name.strip().lower()))
            if uid:
                return uid, False
        if b in self.ids:
            return self.ids[b], False
        for p in self.prefixes:
            rest = b[len(p):] if b.startswith(p) else ""
            if rest in self.ids:
                return self.ids[rest], True
            if rest in self.firsts:  # sulocal_akash, when there's exactly one Akash
                return self.firsts[rest], True
        return None, False


def first_name(first: str | None, display: str | None) -> str:
    """First name from AD, else from a "Last, First" display name."""
    if first and first.strip():
        return first.split()[0].lower()
    if display and "," in display:
        given = display.split(",", 1)[1].split()
        return given[0].lower() if given else ""
    return ""


def _unique_first_names(rows) -> dict[str, str]:
    """First name -> user id, only for names exactly one active person has."""
    seen: dict[str, str | None] = {}
    for r in rows:
        if not r.is_active or r.ad_disabled or r.is_service_account:
            continue
        name = first_name(r.first_name, r.display_name)
        if name:
            seen[name] = None if name in seen else r.id
    return {n: i for n, i in seen.items() if i}


def sign_in_names(q: str) -> list[str]:
    """dhollin also finds machines where they signed in as sulocal_dhollin."""
    from api.core.config import get_settings

    b = bare(q)
    if not b:
        return []
    prefixes = [p.strip().lower() for p in get_settings().account_alias_prefixes.split(",") if p.strip()]
    return [b, *(p + b for p in prefixes)]
