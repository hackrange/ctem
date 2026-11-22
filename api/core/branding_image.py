"""The sign-in page logo: an uploaded image must be the image type it claims."""
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
