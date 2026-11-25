#!/usr/bin/env python3
"""open-ctem backup archive: one password-locked file that can rebuild a server. Author: Tim Rice <tim.j.rice@hackrange.com>"""
# Runs on the host with only the stdlib and python3-cryptography, so a bare server can open it before anything is built.
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from base64 import b64decode, b64encode
from typing import BinaryIO, Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CTEMBAK1"
FORMAT = "open-ctem-backup"
VERSION = 1
CHUNK = 1 << 20
KDF = {"name": "scrypt", "n": 1 << 17, "r": 8, "p": 1}  # about 128 MB of memory per guess
MAX_KDF_MEMORY = 256 << 20
MIN_PASSWORD = 16
PW_ENV = "CTEM_BACKUP_PASSWORD"
MAX_HEADER = 4096
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}(/[a-z0-9][a-z0-9_.-]{0,63}){0,4}$")
_TAG = 16


class BackupError(Exception):
    pass


def password_problem(pw: str) -> str | None:
    """Why a password is too weak, or None when it will do."""
    if len(pw) < MIN_PASSWORD:
        return f"it must be at least {MIN_PASSWORD} characters"
    kinds = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if len(pw) < 24 and kinds < 3:
        return "mix at least three of lowercase, uppercase, digits and symbols, or use 24+ characters"
    if len(set(pw)) < 8:
        return "it repeats too few characters"
    return None


def _key(pw: str, salt: bytes, kdf: dict) -> bytes:
    # The header is untrusted until the first chunk opens, so keep a hostile one from asking for 64 GB of RAM
    n, r, p = kdf.get("n"), kdf.get("r"), kdf.get("p")
    if kdf.get("name") != "scrypt" or not all(type(v) is int for v in (n, r, p)):
        raise BackupError("unsupported key settings in the backup header")
    if not (1 << 14 <= n <= 1 << 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
        raise BackupError("unsupported key settings in the backup header")
    # Each bound alone still allows 2 GiB (n 2^20 with r 16), so cap memory and work together: twice our own settings
    if 128 * r * (n + p) > MAX_KDF_MEMORY or n * r * p > 2 * KDF["n"] * KDF["r"] * KDF["p"]:
        raise BackupError("unsupported key settings in the backup header")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(pw.encode("utf-8"))


def _nonce(prefix: bytes, counter: int, final: bool) -> bytes:
    return prefix + struct.pack(">I", counter) + (b"\x01" if final else b"\x00")


class _SealedWriter:
    """Chunked AES-256-GCM. Counter and last-chunk flag in the nonce stop reordering and quiet truncation."""

    def __init__(self, out: BinaryIO, pw: str):
        salt, self._prefix = os.urandom(16), os.urandom(7)
        header = json.dumps({"format": FORMAT, "version": VERSION, "kdf": KDF, "chunk": CHUNK,
                             "salt": b64encode(salt).decode(), "nonce_prefix": b64encode(self._prefix).decode()},
                            sort_keys=True).encode()
        self._out, self._aad = out, MAGIC + header
        self._aead = AESGCM(_key(pw, salt, KDF))
        self._buf, self._n = bytearray(), 0
        out.write(MAGIC + struct.pack(">I", len(header)) + header)

    def _emit(self, data: bytes, final: bool) -> None:
        ct = self._aead.encrypt(_nonce(self._prefix, self._n, final), data, self._aad)
        self._out.write(struct.pack(">I", len(ct)) + ct)
        self._n += 1

    def write(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= CHUNK:
            self._emit(bytes(self._buf[:CHUNK]), False)
            del self._buf[:CHUNK]

    def close(self) -> None:
        self._emit(bytes(self._buf), True)
        self._buf.clear()


class _SealedReader:
    def __init__(self, src: BinaryIO, pw: str):
        if src.read(len(MAGIC)) != MAGIC:
            raise BackupError("this is not an open-ctem backup file")
        (hlen,) = struct.unpack(">I", _exact(src, 4))
        if hlen > MAX_HEADER:
            raise BackupError("the backup header is damaged")
        header = _exact(src, hlen)
        try:
            meta = json.loads(header)
            salt, self._prefix = b64decode(meta["salt"]), b64decode(meta["nonce_prefix"])
            ok = meta["format"] == FORMAT and meta["version"] == VERSION and len(salt) == 16 and len(self._prefix) == 7
            self._chunk = int(meta["chunk"])
        except (ValueError, KeyError, TypeError) as exc:
            raise BackupError("the backup header is damaged") from exc
        if not ok or not 1024 <= self._chunk <= 1 << 24:
            raise BackupError("this backup was made by a newer version of open-ctem, or is damaged")
        self._src, self._aad = src, MAGIC + header
        self._aead = AESGCM(_key(pw, salt, meta["kdf"]))
        self._n, self._done, self._buf = 0, False, b""
        self._next_len = self._read_len()

    def _read_len(self) -> int | None:
        raw = self._src.read(4)
        if not raw:
            return None
        if len(raw) < 4:
            raise BackupError("the backup file was cut short")
        (n,) = struct.unpack(">I", raw)
        if not _TAG <= n <= self._chunk + _TAG:
            raise BackupError("the backup file is damaged")
        return n

    def _more(self) -> bool:
        if self._done:
            return False
        if self._next_len is None:
            raise BackupError("the backup file was cut short")
        ct = _exact(self._src, self._next_len)
        self._next_len = self._read_len()
        final = self._next_len is None
        try:
            self._buf += self._aead.decrypt(_nonce(self._prefix, self._n, final), ct, self._aad)
        except InvalidTag:
            if self._n == 0:
                raise BackupError("wrong password, or the file is damaged") from None
            raise BackupError("the backup file is damaged or was cut short") from None
        self._n += 1
        self._done = final
        return True

    def read(self, n: int) -> bytes:
        while len(self._buf) < n and self._more():
            pass
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def _exact(src, n: int) -> bytes:
    data = src.read(n)
    if len(data) != n:
        raise BackupError("the backup file was cut short")
    return data


# Inner records: F name | D data | E sha256 | X end. All of it sits inside the sealed stream.
def pack(out_path: str, pw: str, entries: Iterable[tuple[str, str]], manifest: dict) -> None:
    """Write entries (name, path or '-' for stdin) to out_path, atomically, mode 0600."""
    if (why := password_problem(pw)) is not None:
        raise BackupError(f"backup password is too weak: {why}")
    part = out_path + ".part"
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            w = _SealedWriter(out, pw)
            _put(w, "manifest.json", [json.dumps(manifest, sort_keys=True, indent=1).encode()])
            for name, path in entries:
                src = sys.stdin.buffer if path == "-" else open(path, "rb")  # noqa: SIM115
                try:
                    _put(w, name, iter(lambda: src.read(CHUNK), b""))
                finally:
                    if src is not sys.stdin.buffer:
                        src.close()
            w.write(b"X")
            w.close()
            out.flush()
            os.fsync(out.fileno())
        os.replace(part, out_path)
    except BaseException:
        if os.path.exists(part):
            os.unlink(part)
        raise


def _put(w: _SealedWriter, name: str, blocks: Iterable[bytes]) -> None:
    if not NAME_RE.match(name):
        raise BackupError(f"bad entry name {name!r}")
    raw = name.encode()
    w.write(b"F" + struct.pack(">H", len(raw)) + raw)
    digest = hashlib.sha256()
    for block in blocks:
        digest.update(block)
        w.write(b"D" + struct.pack(">I", len(block)) + block)
    w.write(b"E" + digest.digest())


def entries(path: str, pw: str):
    """Yield (name, block iterator) for each entry; the iterator must be drained before the next one."""
    with open(path, "rb") as src:
        r = _SealedReader(src, pw)
        while True:
            kind = _exact(r, 1)
            if kind == b"X":
                if r.read(1) or r._more():
                    raise BackupError("the backup file is damaged")
                return
            if kind != b"F":
                raise BackupError("the backup file is damaged")
            (ln,) = struct.unpack(">H", _exact(r, 2))
            name = _exact(r, ln).decode("utf-8", "replace")
            if not NAME_RE.match(name) or ".." in name.split("/"):
                raise BackupError("the backup file is damaged")
            yield name, _blocks(r)


def _blocks(r: _SealedReader):
    digest = hashlib.sha256()
    while True:
        kind = _exact(r, 1)
        if kind == b"E":
            if _exact(r, 32) != digest.digest():
                raise BackupError("a file inside the backup failed its checksum")
            return
        if kind != b"D":
            raise BackupError("the backup file is damaged")
        (n,) = struct.unpack(">I", _exact(r, 4))
        if n > CHUNK:
            raise BackupError("the backup file is damaged")
        block = _exact(r, n)
        digest.update(block)
        yield block


def extract(path: str, pw: str, dest: str, skip: set[str]) -> list[str]:
    """Open every entry (checking all of them), writing the ones not skipped under dest."""
    root, names = os.path.realpath(dest), []
    for name, blocks in entries(path, pw):
        names.append(name)
        if name in skip:
            for _ in blocks:
                pass
            continue
        target = os.path.realpath(os.path.join(root, name))
        if not target.startswith(root + os.sep):
            raise BackupError("the backup file is damaged")
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            for block in blocks:
                out.write(block)
    if not names or names[0] != "manifest.json":
        raise BackupError("the backup file is damaged")
    return names


def cat(path: str, pw: str, want: str) -> bool:
    """Stream one entry to stdout; the rest are still read so the whole file gets checked."""
    found, out = False, sys.stdout.buffer
    for name, blocks in entries(path, pw):
        for block in blocks:
            if name == want:
                out.write(block)
        found = found or name == want
    out.flush()
    return found


def _password() -> str:
    pw = os.environ.pop(PW_ENV, "")
    if not pw:
        raise BackupError(f"no password given (set {PW_ENV})")
    return pw


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="backup_archive")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack")
    p.add_argument("--out", required=True)
    p.add_argument("--add", action="append", default=[], metavar="NAME=PATH")
    p.add_argument("--meta", action="append", default=[], metavar="KEY=VALUE")
    e = sub.add_parser("extract")
    e.add_argument("--in", dest="src", required=True)
    e.add_argument("--dest", required=True)
    e.add_argument("--skip", action="append", default=[])
    v = sub.add_parser("verify")
    v.add_argument("--in", dest="src", required=True)
    c = sub.add_parser("cat")
    c.add_argument("--in", dest="src", required=True)
    c.add_argument("--name", required=True)
    sub.add_parser("check-password")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "check-password":
            why = password_problem(_password())
            if why:
                print(f"Password is too weak: {why}.", file=sys.stderr)
                return 1
            return 0
        if args.cmd == "pack":
            pairs = [a.split("=", 1) for a in args.add]
            manifest = {"format": FORMAT, "version": VERSION, "entries": [n for n, _ in pairs]}
            manifest.update(dict(m.split("=", 1) for m in args.meta))
            pack(args.out, _password(), [(n, v) for n, v in pairs], manifest)
        elif args.cmd == "verify":
            for name, blocks in entries(args.src, _password()):
                print(f"{name}  {sum(len(b) for b in blocks)} bytes")
        elif args.cmd == "extract":
            extract(args.src, _password(), args.dest, set(args.skip))
        elif not cat(args.src, _password(), args.name):
            print(f"{args.name} is not in this backup.", file=sys.stderr)
            return 3
    except BackupError as exc:
        print(f"Backup error: {exc}.", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"Backup error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
