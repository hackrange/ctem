"""How a user record is shown in the admin and Discovered Users APIs."""
from __future__ import annotations

from api.models.user import User


def ad_summary(u: User) -> dict | None:
    if getattr(u, "ad_disabled", None) is None:
        return None
    iso = lambda v: v.isoformat() if v else None  # noqa: E731
    return {"disabled": bool(u.ad_disabled), "locked_out": bool(u.ad_locked_out),
            "pwd_expired": bool(u.ad_pwd_expired), "pwd_never_expires": bool(u.ad_pwd_never_expires),
            "last_logon": iso(u.ad_last_logon), "pwd_last_set": iso(u.ad_pwd_last_set),
            "pwd_expires": iso(u.ad_pwd_expires), "pwd_days_left": days_left(u)}


def days_left(u: User) -> int | None:
    """Whole days until the AD password expires (negative once it has); None when it never does or isn't known."""
    from datetime import datetime, timezone
    exp = getattr(u, "ad_pwd_expires", None)
    if exp is None or getattr(u, "ad_pwd_never_expires", None):
        return None
    exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
    return (exp - datetime.now(timezone.utc)).days


def _broken(u: User) -> bool:
    """A sign-in account changed outside CTEM (its seal doesn't match): Admin > Users offers Repair."""
    from api.auth.account_seal import intact_loaded
    signs_in = (u.is_local and (u.password_hash or u.is_service_account)) or u.oidc_sub
    return bool(signs_in) and not intact_loaded(u, quiet=True)


def user_summary(u: User, risk: object | None = None) -> dict:
    return {
        "id": str(u.id),
        "username": u.username,
        "email_display": u.email,  # decrypted by EncryptedString on read
        "display_name": getattr(u, "display_name", None),
        "upn": getattr(u, "upn", None),
        "first_name": getattr(u, "first_name", None),
        "last_name": getattr(u, "last_name", None),
        "title": getattr(u, "title", None),
        "phone": getattr(u, "phone", None),
        "mobile": getattr(u, "mobile", None),
        "is_active": u.is_active,
        "is_locked": u.is_locked,
        "is_local": u.is_local,
        "totp_enabled": u.totp_enabled,
        "is_service_account": getattr(u, "is_service_account", False),
        "ad_groups": getattr(u, "ad_groups", None) or [],
        "page_tags": getattr(u, "page_tags", None) or [],
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "ad": ad_summary(u),
        "roles": [{"role_name": ur.role_name} for ur in u.roles],
        "needs_repair": _broken(u),
        "risk_score": risk.score if risk else None,
        "risk_grade": risk.grade if risk else None,
    }
