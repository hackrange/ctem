"""Branding images: an uploaded logo or favicon must be the image type it claims."""
from __future__ import annotations

_MAGIC = {"png": (b"\x89PNG\r\n\x1a\n",), "jpeg": (b"\xff\xd8\xff",), "gif": (b"GIF87a", b"GIF89a"), "webp": (b"RIFF",)}


def real_image(data_url: str) -> bool:
    """A data: logo decodes, is at most 512 KB, and its bytes are the image type it claims (shown on the public
    sign-in page, so nothing else gets through)."""
    import base64
    import binascii
    try:
        head, b64 = data_url.split(",", 1)
        kind = head.split("/", 1)[1].split(";", 1)[0]
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, IndexError, binascii.Error):
        return False
    if kind not in _MAGIC or not raw or len(raw) > 512 * 1024:
        return False
    if kind == "webp" and raw[8:12] != b"WEBP":
        return False
    return raw.startswith(_MAGIC[kind])


# Favicons: PNG or ICO only (never SVG, which can carry script), small, checked by their bytes
ICON_TYPES = {"png": ("image/png", b"\x89PNG\r\n\x1a\n"), "x-icon": ("image/x-icon", b"\x00\x00\x01\x00"),
              "vnd.microsoft.icon": ("image/x-icon", b"\x00\x00\x01\x00")}
ICON_MAX = 128 * 1024


def icon_bytes(data_url: str | None) -> tuple[bytes, str] | None:
    """(bytes, media type) of a stored favicon, or None when it isn't a real small PNG or ICO."""
    import base64
    import binascii
    if not data_url or not data_url.startswith("data:image/"):
        return None
    try:
        head, b64 = data_url.split(",", 1)
        kind = head.split("/", 1)[1].split(";", 1)[0]
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, IndexError, binascii.Error):
        return None
    t = ICON_TYPES.get(kind)
    if t is None or not raw or len(raw) > ICON_MAX or not raw.startswith(t[1]):
        return None
    return raw, t[0]


def icon_version(data_url: str | None) -> str | None:
    """A short hash for the page link, so a new favicon shows at once despite browser caching."""
    import hashlib
    return hashlib.sha256(data_url.encode()).hexdigest()[:10] if icon_bytes(data_url) else None
