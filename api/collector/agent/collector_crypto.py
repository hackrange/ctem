"""Shipper identity + sealed secrets. Same envelope the CTEM web page builds with WebCrypto."""
import base64
import hashlib
import json
import os


def _lib():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise SystemExit("the 'cryptography' Python package is missing; re-run the installer") from None
    return hashes, serialization, padding, rsa, AESGCM


def _oaep():
    hashes, _, padding, _, _ = _lib()
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def new_identity():
    """Fresh RSA-3072 keypair. The private half never leaves this box."""
    _, serialization, _, rsa, _ = _lib()
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def fingerprint(public_pem):
    _, serialization, _, _, _ = _lib()
    key = serialization.load_pem_public_key(public_pem.encode())
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def aad(profile_id, kind, field):
    return f"octem-secret-v1|{profile_id}|{kind}|{field}".encode()


def seal(public_pem, profile_id, kind, field, secret):
    _, serialization, _, _, AESGCM = _lib()
    pub = serialization.load_pem_public_key(public_pem.encode())
    cek, iv = AESGCM.generate_key(bit_length=256), os.urandom(12)
    ct = AESGCM(cek).encrypt(iv, secret.encode(), aad(profile_id, kind, field))
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return json.dumps({"v": 1, "kid": fingerprint(public_pem), "ek": b64(pub.encrypt(cek, _oaep())),
                       "iv": b64(iv), "ct": b64(ct)}, separators=(",", ":"))


class WrongKey(Exception):
    pass


def unseal(private_pem, my_fp, profile_id, kind, field, envelope):
    """Raises WrongKey when CTEM hands us something sealed for a different box (tampering or a stale key)."""
    _, serialization, _, _, AESGCM = _lib()
    env = json.loads(envelope)
    if env.get("v") != 1 or env.get("kid") != my_fp:
        raise WrongKey(f"{kind}.{field} was sealed to a different key")
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    cek = key.decrypt(base64.b64decode(env["ek"]), _oaep())
    return AESGCM(cek).decrypt(base64.b64decode(env["iv"]), base64.b64decode(env["ct"]),
                               aad(profile_id, kind, field)).decode()
