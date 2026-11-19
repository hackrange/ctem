"""open-ctem application entry point."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from api.core.config import get_settings
from api.core.db import close_db, init_db
from api.core.security import RateLimitMiddleware, SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    _validate_config(settings)
    await init_db()
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
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ── Middleware (order matters -- outermost wraps everything) ──────────────
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

    # ── Web UI (must come after API routes) ───────────────────────────────────
    app.mount("/static", StaticFiles(directory="api/web/static"), name="static")
    _register_web_routes(app)

    # ── Health ────────────────────────────────────────────────────────────────
    @app.get("/health", include_in_schema=False)
    async def health():
        return {"status": "ok", "version": settings.app_version}

    # ── Generic error handler -- never leak internals ─────────────────────────
    @app.exception_handler(Exception)
    async def generic_handler(request: Request, exc: Exception):
        import uuid, logging
        req_id = str(uuid.uuid4())
        logging.getLogger("open-ctem").error("Unhandled error [%s]: %s", req_id, exc, exc_info=True)
        return JSONResponse({"error": "An unexpected error occurred", "request_id": req_id}, status_code=500)

    return app


def _register_web_routes(app: FastAPI) -> None:
    from fastapi.responses import HTMLResponse
    from fastapi.templating import Jinja2Templates
    from fastapi import Depends
    from api.auth.middleware import get_current_user

    templates = Jinja2Templates(directory="api/web/templates")

    def _render(template: str):
        """Return a route handler for a standard authenticated page."""
        async def handler(request: Request, current_user=Depends(get_current_user)):
            return templates.TemplateResponse(template, {"request": request, "user": current_user})
        return handler

    # ── Operations ────────────────────────────────────────────────────────────
    app.get("/", response_class=HTMLResponse, include_in_schema=False)(_render("pages/dashboard.html"))
    app.get("/devices", response_class=HTMLResponse, include_in_schema=False)(_render("pages/devices.html"))
    app.get("/vulns", response_class=HTMLResponse, include_in_schema=False)(_render("pages/vulns.html"))

    # ── Analysis ──────────────────────────────────────────────────────────────
    app.get("/threat", response_class=HTMLResponse, include_in_schema=False)(_render("pages/threat.html"))
    app.get("/hunt", response_class=HTMLResponse, include_in_schema=False)(_render("pages/hunt.html"))
    app.get("/attack-paths", response_class=HTMLResponse, include_in_schema=False)(_render("pages/attack_paths.html"))
    app.get("/grc", response_class=HTMLResponse, include_in_schema=False)(_render("pages/grc.html"))
    app.get("/cmdb", response_class=HTMLResponse, include_in_schema=False)(_render("pages/cmdb.html"))

    # ── Settings ──────────────────────────────────────────────────────────────
    app.get("/settings/integrations", response_class=HTMLResponse, include_in_schema=False)(_render("pages/integrations.html"))
    app.get("/settings/tokens", response_class=HTMLResponse, include_in_schema=False)(_render("pages/tokens.html"))

    # ── Admin ─────────────────────────────────────────────────────────────────
    app.get("/admin", response_class=HTMLResponse, include_in_schema=False)(_render("pages/admin.html"))


app = create_app()
