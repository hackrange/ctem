import pytest


def test_logo_must_be_a_real_image():
    import base64

    from api.core.branding_image import real_image as _real_image
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32).decode()
    assert _real_image(f"data:image/png;base64,{png}")
    assert not _real_image(f"data:image/jpeg;base64,{png}")   # says JPEG, is PNG
    html = base64.b64encode(b"<svg onload=alert(1)>").decode()
    assert not _real_image(f"data:image/png;base64,{html}")
    assert not _real_image("data:image/png;base64,not base64!!")
    big = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * (600 * 1024)).decode()
    assert not _real_image(f"data:image/png;base64,{big}")


@pytest.mark.asyncio
async def test_sign_in_page_has_its_own_logo(client_admin, client):
    import base64
    png = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x01" * 16).decode()
    menu = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x02" * 16).decode()
    assert (await client_admin.put("/api/v1/admin/branding", json={"logo_url": menu, "login_logo_url": png})).status_code == 200
    page = (await client.get("/login")).text
    assert png in page and menu not in page   # the sign-in page uses its own
    assert (await client_admin.put("/api/v1/admin/branding", json={"login_logo_url": ""})).status_code == 200
    assert menu in (await client.get("/login")).text   # removed: back to the menu logo
    fake = "data:image/png;base64," + base64.b64encode(b"<html>").decode()
    assert (await client_admin.put("/api/v1/admin/branding", json={"login_logo_url": fake})).status_code == 422
    await client_admin.delete("/api/v1/admin/branding")


import base64  # noqa: E402

ICO = b"\x00\x00\x01\x00\x01\x00\x10\x10" + b"\x00" * 60
PNG = b"\x89PNG\r\n\x1a\n" + b"\x03" * 24


def _data(kind: str, raw: bytes) -> str:
    return f"data:image/{kind};base64," + base64.b64encode(raw).decode()


@pytest.mark.asyncio
async def test_a_favicon_is_a_checked_png_or_ico_served_as_itself(client_admin, client_no_auth):
    put = lambda v: client_admin.put("/api/v1/admin/branding", json={"favicon_url": v})  # noqa: E731
    assert (await put(_data("png", PNG))).status_code == 200
    page = (await client_admin.get("/devices")).text
    assert '<link rel="icon" href="/brand/favicon?v=' in page
    r = await client_no_auth.get("/brand/favicon")          # public, like the sign-in page that shows it
    assert r.status_code == 200 and r.content == PNG and r.headers["content-type"] == "image/png"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert '<link rel="icon"' in (await client_no_auth.get("/login")).text
    assert (await put(_data("x-icon", ICO))).status_code == 200
    r = await client_no_auth.get("/brand/favicon")
    assert r.content == ICO and r.headers["content-type"] == "image/x-icon"
    # not what it claims, too big, or SVG (which can carry script): refused
    assert (await put(_data("png", b"GIF89a" + b"\x00" * 20))).status_code == 422
    assert (await put(_data("png", PNG + b"\x00" * (130 * 1024)))).status_code == 422
    assert (await put("data:image/svg+xml;base64," + base64.b64encode(b"<svg onload=alert(1)>").decode())).status_code == 422
    assert (await put("https://evil.example/x.png")).status_code == 422
    # removed: back to the browser default
    assert (await put("")).status_code == 200
    assert (await client_no_auth.get("/brand/favicon")).status_code == 404
    assert '<link rel="icon"' not in (await client_admin.get("/devices")).text
    await client_admin.delete("/api/v1/admin/branding")
