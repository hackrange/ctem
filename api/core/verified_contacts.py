"""Where CTEM may send a person something that proves who they are: only contacts their SSO/MFA provider verified.

An SMS goes only to the phone of an active SMS MFA factor (the person proved they receive texts there when they
enrolled), never to a directory phone, a voice-only factor or a number someone types in. An email goes only to the
address of an active email MFA factor. The provider fills User.mfa_phone and User.idp (mfa_phone_kind, mfa_email,
factors); Okta's sync does today (api/integrations/okta_ingest.py), and any other provider that fills the same
fields (Ping, Duo, ...) works the same way with nothing changed here."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

RECENT = timedelta(days=7)   # a factor enrolled or changed this recently may be an attacker's: the sender confirms first

_E164 = re.compile(r"^\+[1-9]\d{7,14}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")


def _provider(user) -> str:
    return (user.idp or {}).get("provider") or ("Okta" if getattr(user, "okta_id", None) else "your identity provider")


def mask_phone(p: str) -> str:
    return f"{'•' * 3}-{'•' * 3}-{p[-4:]}"


def mask_email(e: str) -> str:
    local, _, domain = e.partition("@")
    return f"{local[:1]}{'•' * max(2, len(local) - 1)}@{domain}"


def _since(v) -> tuple[str | None, bool]:
    try:
        d = datetime.fromisoformat(str(v)) if v else None
    except ValueError:
        d = None
    if d is not None and d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return (d.isoformat() if d else None), (d is None or datetime.now(timezone.utc) - d < RECENT)


def ineligible(user) -> str | None:
    """Why this account can't be sent a link at all: a service account, or one the provider doesn't hold as active."""
    if getattr(user, "is_service_account", False):
        return "it's a service account"
    if not getattr(user, "is_active", True):
        return "the account is inactive"
    status = (user.idp or {}).get("status")
    if status and status not in ("ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY"):
        return f"the identity provider holds the account as {str(status).lower()}"
    return None


def verified_contacts(user) -> dict:
    """{"sms": {...} | None, "email": {...} | None}; each {"to", "shown", "source", "since", "recent"}. "to" never
    leaves the server. "recent": enrolled or changed in the last 7 days, or the provider didn't say when."""
    idp = user.idp or {}
    out = {"sms": None, "email": None}
    phone = (user.mfa_phone or "").strip()
    if phone and idp.get("mfa_phone_kind") == "sms" and _E164.match(phone):
        since, recent = _since(idp.get("mfa_phone_at"))
        out["sms"] = {"to": phone, "shown": mask_phone(phone), "source": f"{_provider(user)} SMS MFA", "since": since, "recent": recent}
    email = str(idp.get("mfa_email") or "").strip()
    if email and _EMAIL.match(email):
        since, recent = _since(idp.get("mfa_email_at"))
        out["email"] = {"to": email, "shown": mask_email(email), "source": f"{_provider(user)} email MFA", "since": since, "recent": recent}
    return out
