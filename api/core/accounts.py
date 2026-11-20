"""Who is a CTEM account versus a person CTEM merely discovered in the directory."""
from __future__ import annotations

from sqlalchemy import and_, or_

from api.models.user import User


def ctem_account():
    """Accounts that authenticate into CTEM: local logins (incl. token-only service accounts) and SSO sign-ins."""
    return or_(User.is_local == True, User.oidc_sub.isnot(None))  # noqa: E712


def directory_person():
    """People discovered by AD/LDAP (or other feeds) who can't sign in to CTEM."""
    return and_(User.is_local == False, User.oidc_sub.is_(None))  # noqa: E712
