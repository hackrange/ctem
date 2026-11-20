"""Deep links survive sign-in: a link from an email lands where it pointed, never on another site."""
from __future__ import annotations

from urllib.parse import quote, urlsplit

SESSION_KEY = "post_login_next"
_MAX = 2048
_NO_RETURN = ("/login", "/logout", "/auth/", "/api/", "/static/", "/health")


def safe_next(value) -> str | None:
    """A same-site path (with query) or None. Anything that could leave the site is refused."""
    if not isinstance(value, str) or not value or len(value) > _MAX:
        return None
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return None
    if any(parts.path == p.rstrip("/") or parts.path.startswith(p) for p in _NO_RETURN):
        return None
    return value


def login_url_for(path: str, query: str) -> str:
    target = safe_next(path + (f"?{query}" if query else ""))
    return f"/login?next={quote(target, safe='')}" if target and target != "/" else "/login"
