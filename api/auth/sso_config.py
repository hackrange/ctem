"""SSO (OIDC) settings: stored encrypted in the database, environment variables win as the break-glass.

Precedence: OIDC_ISSUER + OIDC_CLIENT_ID in the environment override the stored config, and AUTH_MODE in
the environment overrides the stored sign-in mode. That's what lets an admin get back in when the IdP or
this page is broken. Roles are pinned to people in Admin > Users; SSO never changes them.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.sso_providers import PROVIDERS, issuer_for

SETTING_KEY = "sso.oidc"
MODES = ("local_only", "both", "oidc_only")
NO_ACCESS = "no_access"
DEFAULT_MESSAGE = ("Your sign-in worked, but you don't have access to CTEM yet. "
                   "Ask your CTEM administrator to give your account a role.")
_SCOPE_RE = re.compile(r"^[A-Za-z0-9_:./\-]{1,64}$")


@dataclass
class OidcConfig:
    source: str                    # "database" or "environment"
    provider: str
    issuer: str
    client_id: str
    client_secret: str
    scopes: str
    button_label: str
    default_role: str = NO_ACCESS  # what a brand-new SSO person gets
    no_access_message: str = DEFAULT_MESSAGE


def _env_mode() -> str | None:
    v = os.environ.get("AUTH_MODE", "").strip()
    return v if v in MODES else None


def _env_config() -> OidcConfig | None:
    from api.core.config import get_settings
    s = get_settings()
    if not (os.environ.get("OIDC_ISSUER") and os.environ.get("OIDC_CLIENT_ID")):
        return None
    return OidcConfig(source="environment", provider="custom", issuer=s.oidc_issuer, client_id=s.oidc_client_id,
                      client_secret=s.oidc_client_secret or "", scopes=s.oidc_scopes, button_label="Sign in with SSO")


async def load_raw(db: AsyncSession) -> dict:
    from api.core.encryption import decrypt
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == SETTING_KEY))).scalar_one_or_none()
    if not row or not row.value:
        return {}
    try:
        return json.loads(decrypt(row.value))
    except Exception:
        return {}


async def save_raw(db: AsyncSession, data: dict) -> None:
    from api.core.encryption import encrypt
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == SETTING_KEY))).scalar_one_or_none()
    if row is None:
        row = AppSetting(key=SETTING_KEY, is_sensitive=True)
        db.add(row)
    row.value = encrypt(json.dumps(data))  # the whole blob, secret included, is encrypted at rest


def _from_raw(raw: dict) -> OidcConfig:
    p = PROVIDERS[raw["provider"]]
    return OidcConfig(
        source="database", provider=raw["provider"], issuer=issuer_for(raw["provider"], raw.get("fields", {})),
        client_id=raw["client_id"], client_secret=raw.get("client_secret", ""), scopes=raw.get("scopes") or p["scopes"],
        button_label=raw.get("button_label") or f"Sign in with {p['label']}",
        default_role=raw.get("default_role") or NO_ACCESS, no_access_message=raw.get("no_access_message") or DEFAULT_MESSAGE)


async def effective(db: AsyncSession) -> tuple[str, OidcConfig | None]:
    """(sign-in mode, OIDC config or None). SSO is only offered when it's enabled and complete."""
    raw = await load_raw(db)
    cfg = _env_config()
    if cfg is None and raw.get("enabled"):
        try:
            cfg = _from_raw(raw)
        except (KeyError, ValueError):
            cfg = None
    mode = _env_mode() or (raw.get("mode") if raw.get("enabled") and raw.get("mode") in MODES else "local_only")
    if cfg is None and mode != "local_only":
        mode = "local_only"   # never offer an SSO button that can't work
    return mode, cfg


async def bind_unbound_subjects(db: AsyncSession) -> int:
    """At start: SSO accounts from before issuers were kept (oidc_issuer empty) get the issuer this server is set up
    with, the one that issued their subjects. Sign-in then matches subject and issuer only, so pointing SSO at another
    IdP later can never attach its people to these accounts by a colliding subject. Disabled-but-stored settings still
    name the issuer; with no SSO set up at all the accounts are left alone."""
    from sqlalchemy import update
    from api.models.user import User
    cfg = _env_config()
    if cfg is None:
        raw = await load_raw(db)
        try:
            cfg = _from_raw(raw) if raw.get("provider") else None
        except (KeyError, ValueError):
            cfg = None
    issuer = (cfg.issuer or "").rstrip("/") if cfg else ""
    if not issuer:
        return 0
    res = await db.execute(update(User).where(User.oidc_sub.isnot(None), User.oidc_issuer.is_(None))
                           .values(oidc_issuer=issuer))
    await db.commit()
    return res.rowcount or 0


async def no_access_message(db: AsyncSession) -> str:
    raw = await load_raw(db)
    return raw.get("no_access_message") or DEFAULT_MESSAGE


def env_overrides() -> dict:
    return {"auth_mode": _env_mode(), "oidc": _env_config() is not None}


def validate(body: dict, existing: dict, roles: set[str]) -> dict:
    """Admin input -> stored config. Raises ValueError with a message safe to show."""
    provider = body.get("provider")
    if provider not in PROVIDERS:
        raise ValueError("Pick an identity provider")
    fields = {f["key"]: str((body.get("fields") or {}).get(f["key"], "")).strip()[:256] for f in PROVIDERS[provider]["fields"]}
    issuer_for(provider, fields)  # raises ValueError with a friendly message
    client_id = str(body.get("client_id", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9._:/@-]{4,256}", client_id):
        raise ValueError("Client ID looks wrong")
    secret = body.get("client_secret")
    if secret in (None, "", "__KEEP__"):
        secret = existing.get("client_secret", "") if existing.get("provider") == provider else ""
    secret = str(secret)
    if not 8 <= len(secret) <= 1024 or any(ord(c) < 32 for c in secret):
        raise ValueError("Enter the client secret")
    scopes = " ".join(str(body.get("scopes") or PROVIDERS[provider]["scopes"]).split())
    if "openid" not in scopes.split() or not all(_SCOPE_RE.match(s) for s in scopes.split()) or len(scopes.split()) > 12:
        raise ValueError("Scopes must include openid")
    default_role = str(body.get("default_role") or NO_ACCESS)
    if default_role not in roles:
        raise ValueError("Unknown default role")
    if default_role == "admin":
        raise ValueError("New SSO people can't start as admin; give admin in Admin > Users")
    message = " ".join(str(body.get("no_access_message") or DEFAULT_MESSAGE).split())[:1000]
    mode = body.get("mode", "both")
    if mode not in ("both", "oidc_only"):
        raise ValueError("Mode must be both or oidc_only")
    return {"enabled": bool(body.get("enabled")), "provider": provider, "fields": fields, "client_id": client_id,
            "client_secret": secret, "scopes": scopes, "default_role": default_role, "no_access_message": message,
            "mode": mode, "button_label": str(body.get("button_label") or "").strip()[:60]}


def has_access(role_names: list[str]) -> bool:
    """Signed in is not the same as allowed in: no roles, or only no_access, means stop at the message."""
    return any(r != NO_ACCESS for r in role_names)
