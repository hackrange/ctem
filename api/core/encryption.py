"""AES-256-GCM column encryption. Assumes the DB can be breached.

Two envelopes are read:
  - v1 (every value written before 1.11.4): base64(nonce + ciphertext), no associated data
  - v2: "e2:" + base64(nonce + ciphertext), with associated data naming what the value is: a bare
    encrypt() call, a text column or a JSON column, plus the column itself for the secret-bearing ones. A v2 value
    copied into a column of another kind (or out of a named column) fails authentication instead of opening there.
v1 values keep opening everywhere until they are next written; the secret-bearing ones are rewritten as v2 at start
(api/core/reseal.py). Writes are v2 from 1.11.4 (WRITE_V2). 1.11.3 reads v2, so 1.11.4 can run beside it and roll
back to it, but not to 1.11.2 or earlier, which would read a v2 value as if it were plaintext. The base64 alphabet has no ":", so the prefix never
collides with a v1 value, and stripping it makes the tag fail (v1 is checked with no associated data)."""
from __future__ import annotations

import binascii
import hashlib
import hmac
import logging
import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from api.core.config import get_settings

log = logging.getLogger("open-ctem.encryption")
_NONCE_LEN = 12  # 96-bit GCM nonce
_V2 = "e2:"
_MIN_SEALED = _NONCE_LEN + 16  # nonce + GCM tag
# 1.11.3 read v2 but still wrote v1 (so it could run beside 1.11.2); from 1.11.4 every write is v2
WRITE_V2 = True


def _enc_key() -> bytes:
    return get_settings().encryption_key_bytes


def _search_key() -> bytes:
    return get_settings().encryption_search_key_bytes


def _aad(kind: str, context: str) -> bytes:
    return f"open-ctem|{kind}|{context}".encode()


def encrypt(plaintext: str, *, kind: str = "raw", context: str = "") -> str:
    """Encrypt a string: the v2 envelope, bound to what it is (kind, and context when given), once WRITE_V2 is on;
    until then the v1 envelope every running version can read."""
    nonce = os.urandom(_NONCE_LEN)
    if not WRITE_V2:
        return b64encode(nonce + AESGCM(_enc_key()).encrypt(nonce, plaintext.encode(), None)).decode()
    ct = AESGCM(_enc_key()).encrypt(nonce, plaintext.encode(), _aad(kind, context))
    return _V2 + b64encode(nonce + ct).decode()


def decrypt(ciphertext: str, *, kind: str = "raw", context: str = "") -> str:
    """Decrypt a v2 (bound) or v1 (legacy) envelope. Raises on tamper or on a value bound to something else."""
    if ciphertext.startswith(_V2):
        raw, aad = b64decode(ciphertext[len(_V2):], validate=True), _aad(kind, context)
    else:
        raw, aad = b64decode(ciphertext), None
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return AESGCM(_enc_key()).decrypt(nonce, ct, aad).decode()


def search_hash(value: str) -> str:
    """Deterministic HMAC-SHA256 for indexed lookups on encrypted fields."""
    return hmac.new(_search_key(), value.lower().encode(), hashlib.sha256).hexdigest()


def looks_sealed(value: str) -> bool:
    """Shaped like an envelope (v2 prefix, or base64 of at least nonce + tag) rather than legacy plaintext."""
    if value.startswith(_V2):
        return True
    try:
        return len(b64decode(value, validate=True)) >= _MIN_SEALED
    except (binascii.Error, ValueError):
        return False


def safe_decrypt(ciphertext: str | None, *, kind: str = "raw", context: str = "") -> str | None:
    """Decrypt without exploding on None or legacy plaintext. A value shaped like an envelope that fails
    authentication (tampered, forged, moved from another column, wrong key) is refused: None, never the raw text."""
    if ciphertext is None:
        return None
    if not looks_sealed(ciphertext):
        return ciphertext   # legacy plaintext row -- returned as-is until migrated
    try:
        return decrypt(ciphertext, kind=kind, context=context)
    except Exception:  # noqa: BLE001
        log.warning("encrypted value refused: failed authentication (%s %s)", kind, context or "-")
        return None


# ── SQLAlchemy TypeDecorators ─────────────────────────────────────────────────

class _Encrypted(TypeDecorator):
    impl = Text
    cache_ok = True
    kind = ""

    def __init__(self, context: str = "") -> None:
        """context: name the column ("table.column") to bind its values to it, for columns holding secrets."""
        super().__init__()
        self.context = context

    def open(self, value: str) -> str:
        """Strict decrypt of a stored value as this column would (raises on failure)."""
        return decrypt(value, kind=self.kind, context=self.context)

    def _seal(self, plaintext: str) -> str:
        return encrypt(plaintext, kind=self.kind, context=self.context)

    def _unseal(self, value: str | None) -> str | None:
        return safe_decrypt(value, kind=self.kind, context=self.context)


class EncryptedString(_Encrypted):
    """Transparent AES-256-GCM encryption for text columns."""
    kind = "str"

    def process_bind_param(self, value: str | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        return self._seal(value)

    def process_result_value(self, value: str | None, dialect):  # noqa: ANN001
        return self._unseal(value)


class EncryptedJSON(_Encrypted):
    """Encrypt an arbitrary JSON-serializable value."""
    kind = "json"

    def process_bind_param(self, value: object, dialect):  # noqa: ANN001
        if value is None:
            return None
        import json
        return self._seal(json.dumps(value))

    def process_result_value(self, value: str | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        raw = self._unseal(value)
        if raw is None:
            return None
        import json
        try:
            return json.loads(raw)
        except Exception:
            return raw
