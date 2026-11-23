"""REST API docs for signed-in admins; anonymous visitors don't get a map of the API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse

from api.auth.rbac import require_admin
from api.models.user import User

router = APIRouter(include_in_schema=False)

# Pinned Swagger UI on cdnjs with Subresource Integrity, so a tampered file is refused
_SWAGGER = "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14"
_JS_SRI = "sha384-5zikP7B6JemcHcJalIiFMnUirmSVBr3lZ85ClVPXO7mamWuqUixgyCMUPcKKfZLk"
_CSS_SRI = "sha384-+R8fx41ke61Yq4+j30C8Uh8fbNUEGy8Le9lzVmeMfiUNd+H3q8gN7qW9LM3rbesj"

_PAGE = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>open-ctem API</title>
<link rel="stylesheet" href="{_SWAGGER}/swagger-ui.min.css" integrity="{_CSS_SRI}" crossorigin="anonymous" referrerpolicy="no-referrer">
</head><body><div id="swagger-ui"></div>
<script src="{_SWAGGER}/swagger-ui-bundle.min.js" integrity="{_JS_SRI}" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script>
window.ui = SwaggerUIBundle({{ url: "/api/openapi.json", dom_id: "#swagger-ui", deepLinking: true,
  // Try-it-out calls go out with the session cookie; the server's Origin check covers CSRF
  requestInterceptor: r => {{ r.credentials = "same-origin"; return r; }} }});
</script></body></html>"""


@router.get("/api/openapi.json")
async def openapi_json(request: Request, _: User = Depends(require_admin)):
    return JSONResponse(request.app.openapi())


@router.get("/api/docs")
async def api_docs(_: User = Depends(require_admin)):
    return HTMLResponse(_PAGE)
