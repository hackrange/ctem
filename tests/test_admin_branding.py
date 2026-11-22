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
