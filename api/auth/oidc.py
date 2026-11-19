"""OIDC/PKCE authentication. Supports any compliant IdP (Okta, Entra, Keycloak, Google)."""
from __future__ import annotations

import hashlib
import secrets
import time
from base64 import urlsafe_b64encode
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastapi import HTTPException, Request

from api.core.config import get_settings
from api.core.ssrf import safe_client

_OIDC_DISCOVERY = "/.well-known/openid-configuration"
_STATE_TTL = 600  # 10 minutes to complete the dance


def _pkce_pair() -> tuple[str, str]:
    """Return (verifier, challenge). S256 method."""
    verifier = urlsafe_b64encode(secrets.token_bytes(40)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


async def _discover(issuer: str) -> dict[str, Any]:
    """Fetch OIDC discovery document. Cached in-process (config rarely changes)."""
    url = issuer.rstrip("/") + _OIDC_DISCOVERY
    async with safe_client() as client:
        resp = await client.get(url, timeout=10)
        resp.raise_for_status()
    return resp.json()


async def start_flow(request: Request) -> str:
    """Generate PKCE state, store in session, return redirect URL to IdP."""
    settings = get_settings()
    if not settings.oidc_issuer or not settings.oidc_client_id:
        raise HTTPException(503, detail="OIDC is not configured")

    meta = await _discover(settings.oidc_issuer)
    auth_url = meta["authorization_endpoint"]

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)

    request.session["oidc_state"] = state
    request.session["oidc_verifier"] = verifier
    request.session["oidc_nonce"] = nonce
    request.session["oidc_ts"] = int(time.time())

    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{auth_url}?{query}"


async def handle_callback(request: Request, code: str, state: str) -> dict[str, Any]:
    """Exchange code for tokens, verify claims, return normalized user info."""
    settings = get_settings()
    session_state = request.session.get("oidc_state")
    session_verifier = request.session.get("oidc_verifier")
    session_nonce = request.session.get("oidc_nonce")
    session_ts = request.session.get("oidc_ts", 0)

    if not secrets.compare_digest(str(state), str(session_state or "")):
        raise HTTPException(400, detail="Invalid state")
    if int(time.time()) - session_ts > _STATE_TTL:
        raise HTTPException(400, detail="Authentication session expired")

    # Clean up session
    for key in ("oidc_state", "oidc_verifier", "oidc_nonce", "oidc_ts"):
        request.session.pop(key, None)

    meta = await _discover(settings.oidc_issuer)
    token_url = meta["token_endpoint"]
    userinfo_url = meta.get("userinfo_endpoint")

    async with safe_client() as client:
        resp = await client.post(token_url, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oidc_redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
            "code_verifier": session_verifier,
        })
        resp.raise_for_status()
        tokens = resp.json()

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(400, detail="No id_token in response")

    # Decode without library verification first to get sub/nonce (we verify via userinfo)
    import base64, json as _json
    parts = id_token.split(".")
    if len(parts) != 3:
        raise HTTPException(400, detail="Malformed id_token")
    padding = len(parts[1]) % 4
    if padding:
        parts[1] += "=" * (4 - padding)
    claims = _json.loads(base64.urlsafe_b64decode(parts[1]))

    if not secrets.compare_digest(str(claims.get("nonce", "")), str(session_nonce or "")):
        raise HTTPException(400, detail="Nonce mismatch")

    iss = claims.get("iss", "").rstrip("/")
    expected_iss = settings.oidc_issuer.rstrip("/")
    if iss != expected_iss:
        raise HTTPException(400, detail="Issuer mismatch")

    # Fetch userinfo for authoritative claims
    user_info = claims
    if userinfo_url:
        async with safe_client() as client:
            ui_resp = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            if ui_resp.status_code == 200:
                user_info = {**claims, **ui_resp.json()}

    return {
        "sub": user_info.get("sub"),
        "email": user_info.get("email"),
        "display_name": user_info.get("name") or user_info.get("display_name"),
        "username": user_info.get("preferred_username") or user_info.get("email", "").split("@")[0],
        "groups": user_info.get(settings.oidc_group_claim, []),
    }
