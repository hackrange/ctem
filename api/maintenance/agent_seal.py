"""Seal a password for the host maintenance agent so it never sits in the inbox as plain text.

X25519 to the agent's public key, HKDF-SHA256, AES-256-GCM, with the request id and action bound in as AAD so a
sealed password can't be lifted into a different request. Stdlib plus cryptography only: the host runs this too.
Author: Tim Rice <tim.j.rice@hackrange.com>
"""
from __future__ import annotations

import os
from base64 import b64decode, b64encode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"open-ctem agent seal v1"
_RAW = serialization.Encoding.Raw
_MAX_TOKEN = 2048


class SealError(Exception):
    pass


def _raw_pub(key: X25519PublicKey) -> bytes:
    return key.public_bytes(encoding=_RAW, format=serialization.PublicFormat.Raw)


def _derive(shared: bytes, eph_pub: bytes, host_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO + eph_pub + host_pub).derive(shared)


def new_keypair() -> tuple[bytes, str]:
    """(raw private key, base64 public key)"""
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(encoding=_RAW, format=serialization.PrivateFormat.Raw,
                             encryption_algorithm=serialization.NoEncryption())
    return raw, b64encode(_raw_pub(priv.public_key())).decode()


def public_from_private(raw: bytes) -> str:
    return b64encode(_raw_pub(X25519PrivateKey.from_private_bytes(raw).public_key())).decode()


def seal(host_pub_b64: str, secret: str, context: bytes) -> str:
    try:
        host_pub = b64decode(host_pub_b64.strip(), validate=True)
        host = X25519PublicKey.from_public_bytes(host_pub)
    except ValueError as exc:
        raise SealError("the agent's public key is malformed") from exc
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_pub(eph.public_key())
    key = _derive(eph.exchange(host), eph_pub, host_pub)
    nonce = os.urandom(12)
    return b64encode(eph_pub + nonce + AESGCM(key).encrypt(nonce, secret.encode("utf-8"), context)).decode()


def unseal(priv_raw: bytes, token: str, context: bytes) -> str:
    if not isinstance(token, str) or len(token) > _MAX_TOKEN:
        raise SealError("sealed value is malformed")
    try:
        blob = b64decode(token, validate=True)
        if len(blob) < 32 + 12 + 16:
            raise ValueError("short")
        priv = X25519PrivateKey.from_private_bytes(priv_raw)
        eph_pub, nonce, body = blob[:32], blob[32:44], blob[44:]
        key = _derive(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, _raw_pub(priv.public_key()))
        return AESGCM(key).decrypt(nonce, body, context).decode("utf-8")
    except (ValueError, InvalidTag, UnicodeDecodeError) as exc:
        raise SealError("sealed value does not open") from exc
