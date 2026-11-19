"""AES-256-GCM column encryption. Assumes the DB can be breached."""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from api.core.config import get_settings

_NONCE_LEN = 12  # 96-bit GCM nonce


def _enc_key() -> bytes:
    return get_settings().encryption_key_bytes


def _search_key() -> bytes:
    return get_settings().encryption_search_key_bytes


def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns base64(nonce + ciphertext)."""
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(_enc_key()).encrypt(nonce, plaintext.encode(), None)
    return b64encode(nonce + ct).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64 blob. Raises on tamper."""
    raw = b64decode(ciphertext)
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return AESGCM(_enc_key()).decrypt(nonce, ct, None).decode()


def search_hash(value: str) -> str:
    """Deterministic HMAC-SHA256 for indexed lookups on encrypted fields."""
    return hmac.new(_search_key(), value.lower().encode(), hashlib.sha256).hexdigest()


def safe_decrypt(ciphertext: str | None) -> str | None:
    """Decrypt without exploding on None or legacy plaintext."""
    if ciphertext is None:
        return None
    try:
        return decrypt(ciphertext)
    except Exception:
        # Legacy plaintext row -- return as-is until migrated
        return ciphertext


# ── SQLAlchemy TypeDecorators ─────────────────────────────────────────────────

class EncryptedString(TypeDecorator):
    """Transparent AES-256-GCM encryption for text columns."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        return encrypt(value)

    def process_result_value(self, value: str | None, dialect):  # noqa: ANN001
        return safe_decrypt(value)


class EncryptedJSON(TypeDecorator):
    """Encrypt an arbitrary JSON-serializable value."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: object, dialect):  # noqa: ANN001
        if value is None:
            return None
        import json
        return encrypt(json.dumps(value))

    def process_result_value(self, value: str | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        raw = safe_decrypt(value)
        if raw is None:
            return None
        import json
        try:
            return json.loads(raw)
        except Exception:
            return raw
