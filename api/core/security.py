"""Security middleware: headers, CSRF, rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from collections.abc import Callable

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from api.core.config import get_settings

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
def csp_with(script: str = "", style: str = "") -> str:
    """The app's policy plus exact extra sources for one page (a pinned path on a CDN, never a whole host)."""
    out = _CSP
    if script:
        out = out.replace("script-src 'self' 'unsafe-inline';", f"script-src 'self' 'unsafe-inline' {script};")
    if style:
        out = out.replace("style-src 'self' 'unsafe-inline'", f"style-src 'self' 'unsafe-inline' {style}")
    return out


_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self';"
)


# Pages with no inline script (sign-in) get no 'unsafe-inline' for scripts, so injected markup can't run there
CSP_STRICT_SCRIPT = _CSP.replace("script-src 'self' 'unsafe-inline';", "script-src 'self';")
# JSON is never rendered as a page: it may load nothing and be framed by nothing
_CSP_DATA = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none';"

_ROBOTS = "noindex, nofollow, noarchive, nosnippet, noimageindex, noai, noimageai"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if response.headers.get("x-desk-frame") == "1":   # the service desk panel: its CSP names who may frame it
            del response.headers["x-desk-frame"]
        else:
            response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"  # modern browsers use CSP instead
        if "referrer-policy" not in response.headers:   # the desk panel sets no-referrer
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=(), usb=(), browsing-topics=()"
        # No other site's window keeps a handle on ours (sign-in uses redirects, never pop-ups)
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        data = response.headers.get("content-type", "").startswith("application/json")
        if not request.url.path.startswith("/static/"):   # static files stay loadable as before (logos in mail clients)
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if data and "cache-control" not in response.headers:   # API data is per person: never kept by a browser or proxy
            response.headers["Cache-Control"] = "no-store"
        if "content-security-policy" not in response.headers:   # a page that sets its own (API docs, sign-in) keeps it
            response.headers["Content-Security-Policy"] = _CSP_DATA if data else _CSP
        # Private app: keep it out of search engines and AI crawlers/training
        response.headers["X-Robots-Tag"] = _ROBOTS
        # Remove fingerprinting headers (MutableHeaders uses __delitem__, not pop)
        for _hdr in ("server", "x-powered-by"):
            try:
                del response.headers[_hdr]
            except KeyError:
                pass
        return response


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """CSRF guard: cookie-backed writes must come from our own pages. Bearer callers have no cookie to ride."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method in _SAFE_METHODS or request.headers.get("authorization", "").lower().startswith("bearer "):
            return await call_next(request)
        # Collector agent API never reads cookies, so there is no session for a cross-site request to ride
        if request.url.path.startswith("/api/v1/collector/"):
            return await call_next(request)
        if request.headers.get("sec-fetch-site") == "same-origin":
            return await call_next(request)
        from urllib.parse import urlparse
        source = request.headers.get("origin") or request.headers.get("referer") or ""
        src_host = urlparse(source).hostname if source and source != "null" else None
        allowed = set(get_settings().allowed_hosts_list)
        req_host = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if req_host:
            allowed.add(req_host)
        if src_host and src_host in allowed:
            return await call_next(request)
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Cross-site request blocked"}, status_code=403)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window rate limit per IP on auth endpoints."""

    # Only count actual credential submissions, not page loads
    _AUTH_PATHS = {"/api/v1/auth/token", "/api/v1/auth/login", "/auth/login", "/auth/totp",
                   "/api/v1/profile/password", "/api/v1/auth/totp/verify",
                   "/api/v1/collector/enroll", "/api/v1/collector/enroll-login",
                   "/api/v1/collector/login-check", "/api/v1/admin/maintenance/step-up"}

    def __init__(self, app: ASGIApp, redis_url: str) -> None:
        super().__init__(app)
        self._redis = aioredis.from_url(redis_url, decode_responses=True)
        self._local: dict[str, tuple[int, float]] = {}   # ip -> (count, window start), only while Redis is down

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path in self._AUTH_PATHS:
            ip = _client_ip(request)
            settings = get_settings()
            key = f"rl:ip:{ip}"
            try:
                count = await self._redis.incr(key)
                if count == 1:
                    await self._redis.expire(key, settings.ip_auth_window_seconds)
                if count > settings.ip_auth_max_attempts:
                    from fastapi.responses import JSONResponse
                    return JSONResponse({"detail": "Too many requests"}, status_code=429)
            except HTTPException:
                raise
            except Exception:
                # Redis down: count in this process instead, so the limit still holds (per worker) and nobody is locked out
                logging.getLogger("open-ctem.security").warning("rate limit counted in-process (Redis down?)")
                if self._local_hit(ip, settings.ip_auth_window_seconds) > settings.ip_auth_max_attempts:
                    from fastapi.responses import JSONResponse
                    return JSONResponse({"detail": "Too many requests"}, status_code=429)
        return await call_next(request)

    _LOCAL_MAX = 10_000   # addresses tracked in-process while Redis is unavailable (oldest dropped first)

    def _local_hit(self, ip: str, window: int) -> int:
        """Fixed-window counter kept in memory, bounded, used only while Redis can't be reached."""
        local = self._local
        now = time.monotonic()
        count, start = local.get(ip, (0, now))
        if now - start >= window:
            count, start = 0, now
        local.pop(ip, None)
        while len(local) >= self._LOCAL_MAX:
            del local[next(iter(local))]
        local[ip] = (count + 1, start)
        return count + 1


def _client_ip(request: Request) -> str:
    # nginx already vetted XFF; reading the raw header lets clients pick their IP
    return request.client.host if request.client else "unknown"


# ── CSRF ──────────────────────────────────────────────────────────────────────

def generate_csrf_token(session_id: str) -> str:
    """HMAC-based double-submit CSRF token tied to the session."""
    secret = get_settings().secret_key.encode()
    nonce = secrets.token_hex(16)
    sig = hmac.new(secret, f"{session_id}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{nonce}:{sig}"


def verify_csrf_token(token: str, session_id: str) -> bool:
    """Constant-time CSRF verification."""
    try:
        nonce, sig = token.split(":", 1)
    except ValueError:
        return False
    secret = get_settings().secret_key.encode()
    expected = hmac.new(secret, f"{session_id}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def require_csrf(request: Request, session_id: str) -> None:
    """Raise 403 if CSRF token is missing or invalid on state-changing requests."""
    if request.method in _SAFE_METHODS:
        return
    token = request.headers.get("X-CSRF-Token") or ""
    if not verify_csrf_token(token, session_id):
        raise HTTPException(403, detail="CSRF validation failed")


# ── Generic error response ────────────────────────────────────────────────────

def generic_error(request_id: str, message: str = "An error occurred") -> dict:
    """Never leak internals. Return a generic message + request ID."""
    return {"error": message, "request_id": request_id}
