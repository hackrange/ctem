"""open-ctem application entry point."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from api.core.config import get_settings
from api.core.db import close_db, init_db
from api.core.security import OriginCheckMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    _validate_config(settings)
    await init_db()
    from api.core.db import _session_factory
    from api.core.seed import run_seed
    async with _session_factory() as db:
        await run_seed(db, settings)
    yield
    await close_db()


def _validate_config(settings) -> None:
    """Fail loud at startup if required config is missing."""
    if settings.auth_mode in ("oidc_only", "both"):
        missing = [k for k in ("oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_redirect_uri") if not getattr(settings, k)]
        if missing:
            raise RuntimeError(f"OIDC mode requires: {', '.join(missing)}")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="open-ctem",
        version=settings.app_version,
        # No public API map in production
        docs_url="/api/docs" if settings.debug else None,
        redoc_url="/api/redoc" if settings.debug else None,
        openapi_url="/api/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    # ── Middleware (order matters -- outermost wraps everything) ──────────────
    app.add_middleware(OriginCheckMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, redis_url=settings.redis_url)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="__Host-ctem_session",
        https_only=not settings.debug,
        same_site="lax",
        max_age=settings.access_token_expire_minutes * 60,
    )

    # ── Routers ───────────────────────────────────────────────────────────────
    from api.routes.auth import router as auth_router
    from api.routes.admin import router as admin_router
    from api.routes.devices import router as devices_router
    from api.routes.integrations import router as integrations_router
    from api.routes.cmdb import router as cmdb_router
    from api.routes.vulns import router as vulns_router
    from api.routes.threat import router as threat_router
    from api.routes.grc import router as grc_router
    from api.routes.tokens import router as tokens_router
    from api.routes.hunt import router as hunt_router
    from api.routes.tickets import router as tickets_router
    from api.routes.identity import router as identity_router
    from api.routes.attack_paths import router as attack_paths_router
    from api.routes.grc_exceptions import router as grc_exceptions_router
    from api.routes.tags import router as tags_router

    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(devices_router)
    app.include_router(integrations_router)
    app.include_router(cmdb_router)
    app.include_router(vulns_router)
    app.include_router(threat_router)
    app.include_router(grc_router)
    app.include_router(tokens_router)
    app.include_router(hunt_router)
    app.include_router(tickets_router)
    app.include_router(identity_router)
    app.include_router(attack_paths_router)
    app.include_router(grc_exceptions_router)
    app.include_router(tags_router)

    # ── Web UI (must come after API routes) ───────────────────────────────────
    app.mount("/static", StaticFiles(directory="api/web/static"), name="static")
    _register_web_routes(app)

    # ── Health ────────────────────────────────────────────────────────────────
    @app.get("/health", include_in_schema=False)
    @app.get("/healthz", include_in_schema=False)
    async def health():
        return {"status": "ok", "version": settings.app_version}

    # ── 401: redirect browsers to login, return JSON for API clients ─────────
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        if exc.status_code == 401:
            accept = request.headers.get("accept", "")
            if "text/html" in accept:
                return RedirectResponse(url="/login", status_code=302)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    # ── Generic error handler -- never leak internals ─────────────────────────
    @app.exception_handler(Exception)
    async def generic_handler(request: Request, exc: Exception):
        import uuid, logging
        req_id = str(uuid.uuid4())
        logging.getLogger("open-ctem").error("Unhandled error [%s]: %s", req_id, exc, exc_info=True)
        return JSONResponse({"error": "An unexpected error occurred", "request_id": req_id}, status_code=500)

    return app


async def _get_branding(db) -> dict:
    """Fetch branding settings from AppSetting table."""
    from sqlalchemy import select
    from api.models.settings import AppSetting
    result = await db.execute(select(AppSetting).where(AppSetting.key.like("brand.%")))
    return {s.key.removeprefix("brand."): s.value for s in result.scalars()}


def _register_web_routes(app: FastAPI) -> None:
    from fastapi.responses import HTMLResponse
    from fastapi.templating import Jinja2Templates
    from fastapi import Depends
    from api.auth.middleware import get_current_user
    from api.core.page_access import can_access_page
    from api.core.db import get_session

    templates = Jinja2Templates(directory="api/web/templates")

    def _render(template: str, slug: str):
        """Return a route handler with tag-aware page access control."""
        async def handler(request: Request, current_user=Depends(get_current_user), db=Depends(get_session)):
            if not can_access_page(slug, current_user.role_names, current_user.allowed_page_tags):
                from fastapi import HTTPException
                raise HTTPException(status_code=404)
            branding = await _get_branding(db)
            ctx = {
                "request": request,
                "user": current_user,
                "app_title": branding.get("title", "open-ctem"),
                "accent_color": branding.get("accent_color", "#f5a623"),
                "logo_url": branding.get("logo_url"),
                "org_name": branding.get("org_name"),
            }
            return templates.TemplateResponse(request, template, ctx)
        return handler

    # ── Operations ────────────────────────────────────────────────────────────
    app.get("/", response_class=HTMLResponse, include_in_schema=False)(_render("pages/dashboard.html", "/"))
    app.get("/devices", response_class=HTMLResponse, include_in_schema=False)(_render("pages/devices.html", "/devices"))
    app.get("/users", response_class=HTMLResponse, include_in_schema=False)(_render("pages/users.html", "/users"))
    app.get("/vulns", response_class=HTMLResponse, include_in_schema=False)(_render("pages/vulns.html", "/vulns"))

    # ── Analysis ──────────────────────────────────────────────────────────────
    app.get("/threat", response_class=HTMLResponse, include_in_schema=False)(_render("pages/threat.html", "/threat"))
    app.get("/identity", response_class=HTMLResponse, include_in_schema=False)(_render("pages/identity.html", "/identity"))
    app.get("/hunt", response_class=HTMLResponse, include_in_schema=False)(_render("pages/hunt.html", "/hunt"))
    app.get("/attack-paths", response_class=HTMLResponse, include_in_schema=False)(_render("pages/attack_paths.html", "/attack-paths"))
    app.get("/grc", response_class=HTMLResponse, include_in_schema=False)(_render("pages/grc.html", "/grc"))
    app.get("/cmdb", response_class=HTMLResponse, include_in_schema=False)(_render("pages/cmdb.html", "/cmdb"))

    # ── Settings ──────────────────────────────────────────────────────────────
    app.get("/settings/integrations", response_class=HTMLResponse, include_in_schema=False)(_render("pages/integrations.html", "/settings/integrations"))
    app.get("/settings/tokens", response_class=HTMLResponse, include_in_schema=False)(_render("pages/tokens.html", "/settings/tokens"))

    # ── Admin ─────────────────────────────────────────────────────────────────
    app.get("/admin", response_class=HTMLResponse, include_in_schema=False)(_render("pages/admin.html", "/admin"))

    # ── Profile ───────────────────────────────────────────────────────────────
    app.get("/profile", response_class=HTMLResponse, include_in_schema=False)(_render("pages/profile.html", "/"))


app = create_app()
