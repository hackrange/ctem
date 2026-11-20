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
            "pwd_expires": iso(u.ad_pwd_expires)}


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
        "risk_score": risk.score if risk else None,
        "risk_grade": risk.grade if risk else None,
    }
