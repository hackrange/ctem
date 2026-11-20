"""Admin: single sign-on (OIDC) setup wizard. The client secret goes in, never comes back out."""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import sso_config
from api.auth.rbac import require_admin
from api.auth.sso_providers import PROVIDERS, catalog, issuer_for
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import Role, User

log = logging.getLogger("open-ctem.sso")
router = APIRouter(prefix="/api/v1/admin/sso", tags=["admin"])


async def _roles(db: AsyncSession) -> list[str]:
    return sorted(r for r in (await db.execute(select(Role.name))).scalars())


def _urls(request: Request) -> tuple[str | None, str, str]:
    from api.collector.installer import public_url
    base = public_url(request)
    shown = base or "https://<your CTEM address>"
    return base, f"{shown}/auth/callback", f"{shown}/login"


@router.get("")
async def get_sso(request: Request, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.auth.sso_config import DEFAULT_MESSAGE, NO_ACCESS
    raw = await sso_config.load_raw(db)
    base, redirect_uri, signout_uri = _urls(request)
    mode, cfg = await sso_config.effective(db)
    title = await _app_name(db)
    return {
        "config": {k: v for k, v in raw.items() if k != "client_secret"} | {"client_secret_set": bool(raw.get("client_secret"))},
        "providers": catalog(redirect_uri, signout_uri, title),
        "redirect_uri": redirect_uri, "signout_uri": signout_uri, "public_url_missing": base is None,
        "env": sso_config.env_overrides(), "effective_mode": mode, "active_source": cfg.source if cfg else None,
        "roles": [r for r in await _roles(db) if r != "admin"],
        "defaults": {"default_role": NO_ACCESS, "no_access_message": DEFAULT_MESSAGE, "mode": "both"},
    }


async def _app_name(db: AsyncSession) -> str:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == "brand.title"))).scalar_one_or_none()
    return (row.value if row and row.value else "open-ctem")[:60]


@router.put("")
async def save_sso(body: dict, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    existing = await sso_config.load_raw(db)
    try:
        clean = sso_config.validate(body, existing, set(await _roles(db)))
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from None
    await sso_config.save_raw(db, clean)
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="sso_config_saved",
                    resource_type="sso", detail=f"{clean['provider']}, enabled={clean['enabled']}, mode={clean['mode']}, "
                                                f"default role {clean['default_role']}"))
    await db.commit()
    log.info("SSO settings saved by %s (%s, enabled=%s)", admin.id, clean["provider"], clean["enabled"])
    return {"saved": True, "warning": "AUTH_MODE is set in the server environment and overrides the sign-in mode here"
            if sso_config.env_overrides()["auth_mode"] else None}


@router.post("/test")
async def test_sso(body: dict, _: User = Depends(require_admin)):
    """Checks the IdP from the form's values without saving: discovery, issuer, endpoints, keys, PKCE."""
    from api.auth import oidc
    from api.auth.sso_config import OidcConfig
    provider = body.get("provider")
    if provider not in PROVIDERS:
        raise HTTPException(400, detail="Pick an identity provider")
    try:
        issuer = issuer_for(provider, {k: str(v)[:256] for k, v in (body.get("fields") or {}).items()})
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from None
    cfg = OidcConfig(source="test", provider=provider, issuer=issuer, client_id="", client_secret="",  # nosec B106 - discovery test only, no secret used
                     scopes="openid", button_label="")
    checks = [{"name": "Issuer", "ok": True, "detail": issuer}]
    try:
        meta = await oidc.discover(cfg)
    except oidc.OidcError as exc:
        checks.append({"name": "Discovery document", "ok": False, "detail": str(exc)})
        return {"ok": False, "checks": checks}
    host = urlsplit(issuer).hostname
    checks.append({"name": "Discovery document", "ok": True, "detail": f"issuer matches; endpoints are https on {host}"})
    try:
        keys = await oidc._jwks(meta)
        checks.append({"name": "Signing keys", "ok": bool(keys.keys), "detail": f"{len(keys.keys)} published"})
    except Exception as exc:
        checks.append({"name": "Signing keys", "ok": False, "detail": f"couldn't load ({type(exc).__name__})"})
    pkce = meta.get("code_challenge_methods_supported")
    checks.append({"name": "PKCE (S256)", "ok": pkce is None or "S256" in pkce,
                   "detail": "supported" if pkce and "S256" in pkce else "not advertised; most IdPs still accept it" if pkce is None else "S256 not supported"})
    code = "code" in (meta.get("response_types_supported") or ["code"])
    checks.append({"name": "Authorization code flow", "ok": code, "detail": "supported" if code else "not offered"})
    auth = meta.get("token_endpoint_auth_methods_supported")
    post = auth is None or "client_secret_post" in auth
    checks.append({"name": "Client secret (post)", "ok": post,
                   "detail": "supported" if post else f"IdP offers {', '.join(auth)[:120]}; enable client_secret_post"})
    return {"ok": all(c["ok"] for c in checks), "checks": checks,
            "next": "Save, then sign in from a private window to finish (that also proves the client ID and secret)."}
