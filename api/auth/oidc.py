"""OIDC authorization code + PKCE sign-in for Okta, Auth0, PingOne, Entra ID (or any compliant IdP).

ID tokens are verified against the IdP's published keys (asymmetric algorithms only): issuer, audience,
expiry, issued-at and nonce all have to check out. Every endpoint the discovery document names must be
https on the issuer's own host, so a tampered discovery document can't send codes or secrets elsewhere.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
from base64 import urlsafe_b64encode
from typing import Any
from urllib.parse import urlencode, urlsplit

import jwt
from fastapi import HTTPException, Request

from api.auth.sso_config import OidcConfig
from api.core.ssrf import safe_client

log = logging.getLogger("open-ctem.oidc")
_DISCOVERY = "/.well-known/openid-configuration"
_STATE_TTL = 600  # ten minutes to finish at the IdP
_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]


class OidcError(Exception):
    """Something about the IdP setup is wrong; the message is safe to show an admin."""


def _pkce_pair() -> tuple[str, str]:
    verifier = urlsafe_b64encode(secrets.token_bytes(40)).rstrip(b"=").decode()
    challenge = urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _same_host(url: str, issuer: str) -> bool:
    u, i = urlsplit(url), urlsplit(issuer)
    return u.scheme == "https" and bool(u.hostname) and u.hostname == i.hostname


async def discover(cfg: OidcConfig) -> dict[str, Any]:
    url = cfg.issuer.rstrip("/") + _DISCOVERY
    if not url.startswith("https://"):
        raise OidcError("the issuer must use https")
    try:
        async with safe_client() as client:
            resp = await client.get(url, timeout=10)
    except Exception as exc:
        raise OidcError(f"couldn't reach {urlsplit(url).hostname} ({type(exc).__name__})") from None
    if resp.status_code != 200:
        raise OidcError(f"discovery returned HTTP {resp.status_code}; check the domain, tenant or environment ID")
    try:
        meta = resp.json()
    except ValueError:
        raise OidcError("discovery didn't return JSON") from None
    if str(meta.get("issuer", "")).rstrip("/") != cfg.issuer.rstrip("/"):
        raise OidcError(f"issuer mismatch: the IdP says {str(meta.get('issuer'))[:120]}")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not meta.get(key) or not _same_host(str(meta[key]), cfg.issuer):
            raise OidcError(f"{key} must be https on {urlsplit(cfg.issuer).hostname}")
    if meta.get("userinfo_endpoint") and not _same_host(str(meta["userinfo_endpoint"]), cfg.issuer):
        meta.pop("userinfo_endpoint")
    return meta


async def _jwks(meta: dict) -> jwt.PyJWKSet:
    async with safe_client() as client:
        resp = await client.get(meta["jwks_uri"], timeout=10)
    if resp.status_code != 200:
        raise OidcError(f"signing keys returned HTTP {resp.status_code}")
    return jwt.PyJWKSet.from_dict(resp.json())


async def start_flow(request: Request, cfg: OidcConfig, redirect_uri: str) -> str:
    try:
        meta = await discover(cfg)
    except OidcError as exc:
        log.warning("SSO start failed: %s", exc)
        raise HTTPException(503, detail="Single sign-on is unavailable right now") from None
    verifier, challenge = _pkce_pair()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    request.session.update({"oidc_state": state, "oidc_verifier": verifier, "oidc_nonce": nonce,
                            "oidc_ts": int(time.time())})
    query = urlencode({"response_type": "code", "client_id": cfg.client_id, "redirect_uri": redirect_uri,
                       "scope": cfg.scopes, "state": state, "nonce": nonce, "code_challenge": challenge,
                       "code_challenge_method": "S256"})
    return f"{meta['authorization_endpoint']}?{query}"


async def handle_callback(request: Request, code: str, state: str, cfg: OidcConfig, redirect_uri: str) -> dict[str, Any]:
    """Exchange the code, verify the ID token, and return normalized claims."""
    s_state, verifier = request.session.get("oidc_state"), request.session.get("oidc_verifier")
    nonce, started = request.session.get("oidc_nonce"), int(request.session.get("oidc_ts", 0))
    for key in ("oidc_state", "oidc_verifier", "oidc_nonce", "oidc_ts"):
        request.session.pop(key, None)  # one use only, whatever happens next
    if not s_state or not secrets.compare_digest(str(state), str(s_state)):
        raise HTTPException(400, detail="Invalid sign-in state")
    if time.time() - started > _STATE_TTL:
        raise HTTPException(400, detail="Sign-in took too long; please try again")
    try:
        meta = await discover(cfg)
        async with safe_client() as client:
            resp = await client.post(meta["token_endpoint"], data={
                "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "client_id": cfg.client_id, "client_secret": cfg.client_secret, "code_verifier": verifier})
        if resp.status_code != 200:
            log.warning("SSO token exchange failed: HTTP %s", resp.status_code)
            raise HTTPException(400, detail="Sign-in failed at the identity provider")
        tokens = resp.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise HTTPException(400, detail="Sign-in failed at the identity provider")
        header = jwt.get_unverified_header(id_token)
        if header.get("alg") not in _ALGS:
            raise HTTPException(400, detail="Sign-in failed: unsupported token signature")
        keys = await _jwks(meta)
        key = next((k for k in keys.keys if k.key_id == header.get("kid")), None)
        if key is None and len(keys.keys) == 1 and not header.get("kid"):
            key = keys.keys[0]
        if key is None:
            raise HTTPException(400, detail="Sign-in failed: unknown signing key")
        claims = jwt.decode(id_token, key.key, algorithms=[header["alg"]], audience=cfg.client_id,
                            issuer=meta["issuer"], leeway=60,
                            options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except OidcError as exc:
        log.warning("SSO callback failed: %s", exc)
        raise HTTPException(503, detail="Single sign-on is unavailable right now") from None
    except jwt.PyJWTError as exc:
        log.warning("SSO ID token rejected: %s", exc)
        raise HTTPException(400, detail="Sign-in failed: the identity token didn't verify") from None
    if not nonce or not secrets.compare_digest(str(claims.get("nonce", "")), str(nonce)):
        raise HTTPException(400, detail="Sign-in failed: nonce mismatch")
    if isinstance(claims.get("aud"), list) and len(claims["aud"]) > 1 and claims.get("azp") != cfg.client_id:
        raise HTTPException(400, detail="Sign-in failed: token was issued to another app")
    info = dict(claims)
    if meta.get("userinfo_endpoint") and tokens.get("access_token"):
        try:
            async with safe_client() as client:
                ui = await client.get(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {tokens['access_token']}"})
            if ui.status_code == 200 and str(ui.json().get("sub")) == str(claims["sub"]):
                info = {**ui.json(), **claims}  # verified token claims win over userinfo
        except Exception:
            log.info("SSO userinfo unavailable; using ID token claims only")
    email = info.get("email") or info.get("upn") or ""
    return {"sub": str(claims["sub"]), "email": email or None,
            "display_name": info.get("name") or info.get("display_name"),
            "username": (info.get("preferred_username") or email or str(claims["sub"]))[:256]}
