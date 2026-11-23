"""Who is a CTEM account versus a person CTEM merely discovered in the directory."""
from __future__ import annotations

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.user import User


def ctem_account():
    """Accounts that authenticate into CTEM: local logins (incl. token-only service accounts) and SSO sign-ins."""
    return or_(User.is_local == True, User.oidc_sub.isnot(None))  # noqa: E712


def directory_person():
    """People discovered by AD/LDAP (or other feeds) who can't sign in to CTEM."""
    return and_(User.is_local == False, User.oidc_sub.is_(None))  # noqa: E712


def same_name(name: str):
    """Usernames match regardless of case: Admin, ADMIN and admin are one account."""
    return func.lower(User.username) == name.strip().lower()


async def find_login(db: AsyncSession, name: str, *where, options=()) -> User | None:
    """The sign-in account for a typed username, case-insensitively.
    Older data may hold two accounts that differ only by case: then only an exact match counts, never a guess."""
    rows = (await db.execute(select(User).where(same_name(name), *where).options(*options).limit(5))).scalars().all()
    if len(rows) == 1:
        return rows[0]
    return next((u for u in rows if u.username == name.strip()), None)
