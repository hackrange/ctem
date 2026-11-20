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
        # Docs are served by api.routes.api_docs to signed-in admins and cyber analysts only
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
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
    from api.routes.api_docs import router as api_docs_router
    from api.routes.device_assign import router as device_assign_router
    from api.routes.devices import router as devices_router
    from api.routes.integrations import router as integrations_router
    from api.routes.cmdb import router as cmdb_router
    from api.routes.vulns import router as vulns_router
    from api.routes.threat import router as threat_router
    from api.routes.grc import router as grc_router
    from api.routes.tokens import router as tokens_router
    from api.routes.hunt import router as hunt_router
    from api.routes.tickets import router as tickets_router
    from api.routes.ticket_assist import router as ticket_assist_router
    from api.routes.ai_usage import router as ai_usage_router
    from api.routes.admin_export import router as admin_export_router
    from api.routes.identity import router as identity_router
    from api.routes.attack_paths import router as attack_paths_router
    from api.routes.grc_exceptions import router as grc_exceptions_router
    from api.routes.tags import router as tags_router
    from api.routes.collector_agent import router as collector_agent_router
    from api.routes.collectors_admin import router as collectors_admin_router
    from api.routes.grc_checks import router as grc_checks_router
    from api.routes.grc_data import router as grc_data_router
    from api.routes.grc_assess import router as grc_assess_router
    from api.routes.grc_risk_edit import router as grc_risk_edit_router
    from api.routes.curated_rules import router as curated_rules_router
    from api.routes.grc_service_token import router as grc_service_token_router
    from api.routes.directory_users import router as directory_users_router
    from api.routes.admin_sso import router as admin_sso_router

    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(api_docs_router)
    app.include_router(device_assign_router)  # before devices so /assignable-users never hits /{device_id}
    app.include_router(devices_router)
    app.include_router(integrations_router)
    app.include_router(cmdb_router)
    app.include_router(vulns_router)
    app.include_router(threat_router)
    app.include_router(grc_router)
    app.include_router(tokens_router)
    app.include_router(hunt_router)
    app.include_router(ai_usage_router)
    app.include_router(admin_export_router)
    app.include_router(ticket_assist_router)  # before tickets so /ticket-options never hits a {finding_id} route
    app.include_router(tickets_router)
    app.include_router(identity_router)
    app.include_router(attack_paths_router)
    app.include_router(grc_exceptions_router)
    app.include_router(tags_router)
    app.include_router(collector_agent_router)
    app.include_router(collectors_admin_router)
    app.include_router(grc_checks_router)
    app.include_router(grc_data_router)
    app.include_router(grc_assess_router)
    app.include_router(grc_risk_edit_router)
    app.include_router(curated_rules_router)
    app.include_router(grc_service_token_router)
    app.include_router(directory_users_router)
    app.include_router(admin_sso_router)

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
                # Remember the page (e.g. a link from an email) so sign-in lands there
                from api.auth.return_to import login_url_for
                target = login_url_for(request.url.path, request.url.query) if request.method == "GET" else "/login"
                return RedirectResponse(url=target, status_code=302)
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

    from api.web.assets import install as _install_assets

    _install_assets(templates)

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

    from fastapi.responses import PlainTextResponse

    # Public on purpose: crawlers read it before anything else. Everything is disallowed.
    _AI_BOTS = ("GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-User", "Claude-SearchBot",
                "anthropic-ai", "Google-Extended", "GoogleOther", "CCBot", "PerplexityBot", "Perplexity-User",
                "Bytespider", "Applebot-Extended", "Meta-ExternalAgent", "Meta-ExternalFetcher", "Amazonbot",
                "cohere-ai", "cohere-training-data-crawler", "Diffbot", "ImagesiftBot", "YouBot", "MistralAI-User")
    _ROBOTS_TXT = "".join(f"User-agent: {b}\nDisallow: /\n\n" for b in _AI_BOTS) + "User-agent: *\nDisallow: /\n"
    app.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)(lambda: _ROBOTS_TXT)

    # ── Operations ────────────────────────────────────────────────────────────
    app.get("/", response_class=HTMLResponse, include_in_schema=False)(_render("pages/dashboard.html", "/"))
    app.get("/devices", response_class=HTMLResponse, include_in_schema=False)(_render("pages/devices.html", "/devices"))
    # Detail pages share their list page's access rule; the API re-checks the object itself
    app.get("/devices/{device_id}", response_class=HTMLResponse, include_in_schema=False)(_render("pages/device_detail.html", "/devices"))
    app.get("/users", response_class=HTMLResponse, include_in_schema=False)(_render("pages/users.html", "/users"))
    app.get("/vulns", response_class=HTMLResponse, include_in_schema=False)(_render("pages/vulns.html", "/vulns"))
    app.get("/vulns/{vuln_id}", response_class=HTMLResponse, include_in_schema=False)(_render("pages/vuln_detail.html", "/vulns"))

    # ── Analysis ──────────────────────────────────────────────────────────────
    app.get("/threat", response_class=HTMLResponse, include_in_schema=False)(_render("pages/threat.html", "/threat"))
    app.get("/threat/alert", response_class=HTMLResponse, include_in_schema=False)(_render("pages/threat_alert.html", "/threat"))
    app.get("/identity", response_class=HTMLResponse, include_in_schema=False)(_render("pages/identity.html", "/identity"))
    app.get("/hunt", response_class=HTMLResponse, include_in_schema=False)(_render("pages/hunt.html", "/hunt"))
    app.get("/attack-paths", response_class=HTMLResponse, include_in_schema=False)(_render("pages/attack_paths.html", "/attack-paths"))
    app.get("/grc", response_class=HTMLResponse, include_in_schema=False)(_render("pages/grc.html", "/grc"))
    app.get("/grc/checks/{check_type}", response_class=HTMLResponse, include_in_schema=False)(_render("pages/grc_check.html", "/grc"))
    app.get("/grc/assessments/{assessment_id}", response_class=HTMLResponse, include_in_schema=False)(_render("pages/grc_assessment.html", "/grc"))
    app.get("/cmdb", response_class=HTMLResponse, include_in_schema=False)(_render("pages/cmdb.html", "/cmdb"))

    # ── Settings ──────────────────────────────────────────────────────────────
    app.get("/settings/integrations", response_class=HTMLResponse, include_in_schema=False)(_render("pages/integrations.html", "/settings/integrations"))
    app.get("/settings/sso", response_class=HTMLResponse, include_in_schema=False)(_render("pages/sso.html", "/settings/sso"))
    app.get("/settings/shippers", response_class=HTMLResponse, include_in_schema=False)(_render("pages/shippers.html", "/settings/shippers"))
    app.get("/settings/tokens", response_class=HTMLResponse, include_in_schema=False)(_render("pages/tokens.html", "/settings/tokens"))

    # ── Admin ─────────────────────────────────────────────────────────────────
    app.get("/admin", response_class=HTMLResponse, include_in_schema=False)(_render("pages/admin.html", "/admin"))

    # ── Profile ───────────────────────────────────────────────────────────────
    app.get("/profile", response_class=HTMLResponse, include_in_schema=False)(_render("pages/profile.html", "/"))


app = create_app()
