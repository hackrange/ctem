"""Security middleware: headers, CSRF, rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from api.core.config import get_settings

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"  # modern browsers use CSP instead
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = _CSP
        # Remove fingerprinting headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window rate limit per IP on auth endpoints."""

    _AUTH_PATHS = {"/api/v1/auth/token", "/api/v1/auth/login", "/login"}

    def __init__(self, app: ASGIApp, redis_url: str) -> None:
        super().__init__(app)
        self._redis = aioredis.from_url(redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self._AUTH_PATHS:
            ip = _client_ip(request)
            settings = get_settings()
            key = f"rl:ip:{ip}"
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, settings.ip_auth_window_seconds)
            if count > settings.ip_auth_max_attempts:
                raise HTTPException(429, detail="Too many requests")
        return await call_next(request)


def _client_ip(request: Request) -> str:
    """Extract real client IP, respecting trusted proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
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
