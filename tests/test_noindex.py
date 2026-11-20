"""The app stays out of search engines and AI crawlers."""
import pytest


@pytest.mark.asyncio
async def test_robots_txt_is_public_and_disallows_all(client_no_auth):
    r = await client_no_auth.get("/robots.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "User-agent: *\nDisallow: /" in r.text
    for bot in ("GPTBot", "ClaudeBot", "Google-Extended", "CCBot", "PerplexityBot"):
        assert f"User-agent: {bot}\nDisallow: /" in r.text


@pytest.mark.asyncio
async def test_noindex_header_everywhere(client_no_auth, client_admin):
    for client, path in ((client_no_auth, "/login"), (client_no_auth, "/robots.txt"), (client_no_auth, "/api/v1/devices"),
                         (client_admin, "/devices"), (client_admin, "/static/css/style.css")):
        r = await client.get(path)
        assert "noindex" in r.headers.get("x-robots-tag", ""), path
        assert "noai" in r.headers["x-robots-tag"]


@pytest.mark.asyncio
async def test_login_page_has_robots_meta(client_no_auth):
    html = (await client_no_auth.get("/login")).text
    assert '<meta name="robots" content="noindex' in html
