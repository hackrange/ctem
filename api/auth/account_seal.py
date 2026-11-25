"""Keyed seals over what lets an account in (CTE-031). Whoever can write to the database but doesn't hold the app's
keys could otherwise take over an account without touching a secret: switch its MFA off so it re-enrolls, write in
a password hash they know, give their own account the admin role, or add an API token row for someone else. Each
account carries an HMAC over its sign-in state and roles, each API token one over itself; a request, a sign-in step
or a token whose seal doesn't match is refused. Only the app's own changes re-seal. Existing rows are sealed once,
by `python -m api.maintenance.seal_accounts` (the installer runs it when an upgrade crosses 1.13.2), never by
anything stored in the database.

A database writer can still replay a row's own earlier state with its earlier seal (an old backup's password hash,
say): rotate what such a copy may hold."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.auth")
FIX = "docker compose exec app python -m api.maintenance.seal_accounts"


def derived_key(label: bytes) -> bytes:
    """A key of its own for one purpose, from the encryption key (HKDF). Never from the search key: a search hash is
    HMAC(search key, text) and text an outsider chooses gets stored as one, so a key built that way can leak."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from api.core import encryption as enc
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(enc._enc_key())


def _key() -> bytes:
    return derived_key(b"open-ctem|account-seal|v2")


def _mac(parts: list) -> str:
    return hmac.new(_key(), json.dumps(parts, separators=(",", ":"), default=str).encode(), hashlib.sha256).hexdigest()


def _when(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")


SEALED = ("is_local", "is_active", "password_hash", "totp_enabled", "totp_secret", "recovery_codes", "oidc_sub",
          "oidc_issuer", "password_change_required", "password_expires_at", "is_locked", "sessions_valid_after",
          "page_tags", "auth_seal")


def user_seal(u, roles) -> str:
    return _mac(["user", str(u.id), bool(u.is_local), bool(u.is_active), u.password_hash or "", bool(u.totp_enabled),
                 u.totp_secret or "", sorted(u.recovery_codes or []), sorted(set(roles)), u.oidc_sub or "",
                 u.oidc_issuer or "", bool(u.password_change_required), _when(u.password_expires_at), bool(u.is_locked),
                 _when(u.sessions_valid_after), sorted(u.page_tags or [])])


def token_seal(t) -> str:
    return _mac(["token", str(t.id), str(t.user_id), t.token_hash or "", sorted(t.allowed_ips or []), _when(t.expires_at),
                 bool(t.is_active)])


async def roles_of(db: AsyncSession, user_id: str) -> list[str]:
    from api.models.user import UserRole
    return list((await db.execute(select(UserRole.role_name).where(UserRole.user_id == str(user_id)))).scalars())


async def reseal(db: AsyncSession, user, roles: list[str]) -> None:
    """After the app itself changed this account: seal its new state with the roles the caller checked or set.
    Never re-read here: a role slipped into the table meanwhile would be sealed in with the rest."""
    await db.flush()
    user.auth_seal = user_seal(user, roles)


async def verified_roles(db: AsyncSession, user) -> list[str] | None:
    """This account's roles if its seal holds, else None. Reads the row again under a lock first, so a change made
    meanwhile by another request is checked, not half-overwritten (Postgres; SQLite has no row locks)."""
    await db.refresh(user, attribute_names=list(SEALED), with_for_update=True)   # the sealed columns only
    roles = await roles_of(db, user.id)
    return roles if _check(user, roles) else None


async def checked(db: AsyncSession, user) -> list[str]:
    """For an admin changing an account: its roles if its seal holds; an account changed outside CTEM is repaired
    instead (Admin > Users > Repair), so no change of ours seals what someone else wrote."""
    from fastapi import HTTPException
    roles = await verified_roles(db, user)
    if roles is None:
        raise HTTPException(409, detail="This account was changed outside CTEM. Repair it first (Admin > Users).")
    return roles


async def intact(db: AsyncSession, user) -> bool:
    return await verified_roles(db, user) is not None


def loaded_roles(user) -> list[str]:
    return [r.role_name for r in user.roles]


def intact_loaded(user, quiet: bool = False) -> bool:
    """For a user loaded with its roles (the auth middleware; Admin > Users shows it, quietly)."""
    return _check(user, loaded_roles(user), quiet)


def _check(user, roles, quiet: bool = False) -> bool:
    ok = bool(user.auth_seal) and hmac.compare_digest(user.auth_seal, user_seal(user, roles))
    if not ok and not quiet:
        log.warning("account %s refused: its sign-in state doesn't match its seal (changed outside CTEM, or never "
                    "sealed: run `%s`)", user.id, FIX)
    return ok


def collector_seal(t) -> str:
    """A shipper's credential: a planted row would be sent future secrets sealed to its own key."""
    return _mac(["collector", str(t.id), str(t.profile_id), t.token_hash or "", t.public_key or "", t.key_fp or "",
                 sorted(t.allowed_ips or []), bool(t.is_active), sorted((t.approved or {}).items())])


def seal_collector(t) -> None:
    t.seal = collector_seal(t)


def collector_intact(t) -> bool:
    ok = bool(t.seal) and hmac.compare_digest(t.seal, collector_seal(t))
    if not ok:
        log.warning("shipper credential %s refused: it doesn't match its seal", t.id)
    return ok


def seal_token(t) -> None:
    t.seal = token_seal(t)


def token_intact(t) -> bool:
    ok = bool(t.seal) and hmac.compare_digest(t.seal, token_seal(t))
    if not ok:
        log.warning("API token %s refused: it doesn't match its seal", t.id)
    return ok
