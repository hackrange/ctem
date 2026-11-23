"""Backup archive: round trip, wrong password, tampering, truncation and hostile input."""
from __future__ import annotations

import json
import os
import struct

import pytest

from api.maintenance import backup_archive as ba

PW = "Correct-Horse-Battery-9"  # nosec  # noqa: S105 -- test-only example password


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    monkeypatch.setattr(ba, "KDF", {"name": "scrypt", "n": 1 << 14, "r": 8, "p": 1})


def _make(tmp_path, files: dict[str, bytes], pw: str = PW) -> str:
    srcs = []
    for i, (name, data) in enumerate(files.items()):
        p = tmp_path / f"src{i}"
        p.write_bytes(data)
        srcs.append((name, str(p)))
    out = str(tmp_path / "x.ctembak")
    ba.pack(out, pw, srcs, {"format": ba.FORMAT, "host": "server001"})
    return out


def _read_all(path: str, pw: str = PW) -> dict[str, bytes]:
    return {name: b"".join(blocks) for name, blocks in ba.entries(path, pw)}


def test_round_trip_keeps_every_byte(tmp_path):
    big = os.urandom(ba.CHUNK * 2 + 12345)
    path = _make(tmp_path, {"db/openctem.dump": big, "env/dotenv": b"A=1\n", "host/empty": b""})
    got = _read_all(path)
    assert list(got) == ["manifest.json", "db/openctem.dump", "env/dotenv", "host/empty"]
    assert got["db/openctem.dump"] == big and got["env/dotenv"] == b"A=1\n" and got["host/empty"] == b""
    assert json.loads(got["manifest.json"])["host"] == "server001"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_extract_writes_files_and_skips(tmp_path):
    path = _make(tmp_path, {"env/dotenv": b"K=v\n", "db/openctem.dump": b"dump"})
    dest = tmp_path / "out"
    dest.mkdir()
    names = ba.extract(path, PW, str(dest), {"db/openctem.dump"})
    assert names == ["manifest.json", "env/dotenv", "db/openctem.dump"]
    assert (dest / "env/dotenv").read_bytes() == b"K=v\n"
    assert not (dest / "db/openctem.dump").exists()


def test_cat_streams_one_entry(tmp_path, capfdbinary):
    path = _make(tmp_path, {"a": b"first", "b": b"second"})
    assert ba.cat(path, PW, "b") is True
    assert capfdbinary.readouterr().out == b"second"


def test_wrong_password(tmp_path):
    path = _make(tmp_path, {"a": b"x"})
    with pytest.raises(ba.BackupError, match="wrong password"):
        _read_all(path, "Totally-Different-Pass-1")


@pytest.mark.parametrize("where", [0.3, 0.6, 0.95])
def test_any_flipped_byte_is_caught(tmp_path, where):
    path = _make(tmp_path, {"a": os.urandom(ba.CHUNK + 500)})
    raw = bytearray(open(path, "rb").read())
    raw[int(len(raw) * where)] ^= 0x01
    open(path, "wb").write(raw)
    with pytest.raises(ba.BackupError):
        _read_all(path)


def test_truncation_is_caught(tmp_path):
    path = _make(tmp_path, {"a": os.urandom(ba.CHUNK * 2 + 10)})
    raw = open(path, "rb").read()
    header_end = len(ba.MAGIC) + 4 + struct.unpack(">I", raw[8:12])[0]
    first_chunk_end = header_end + 4 + ba.CHUNK + 16
    for cut in (first_chunk_end, first_chunk_end + 100, len(raw) - 1):
        open(path, "wb").write(raw[:cut])
        with pytest.raises(ba.BackupError):
            _read_all(path)


def test_trailing_garbage_is_caught(tmp_path):
    path = _make(tmp_path, {"a": b"x"})
    with open(path, "ab") as f:
        f.write(struct.pack(">I", 40) + os.urandom(40))
    with pytest.raises(ba.BackupError):
        _read_all(path)


def test_hostile_kdf_header_is_refused_before_any_work(tmp_path):
    header = json.dumps({"format": ba.FORMAT, "version": 1, "chunk": ba.CHUNK, "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                         "nonce_prefix": "AAAAAAAAAA==", "kdf": {"name": "scrypt", "n": 1 << 30, "r": 8, "p": 1}}).encode()
    path = tmp_path / "evil.ctembak"
    path.write_bytes(ba.MAGIC + struct.pack(">I", len(header)) + header)
    with pytest.raises(ba.BackupError, match="key settings"):
        _read_all(str(path))


def test_not_a_backup(tmp_path):
    path = tmp_path / "x.ctembak"
    path.write_bytes(b"PK\x03\x04 not ours")
    with pytest.raises(ba.BackupError, match="not an open-ctem backup"):
        _read_all(str(path))


@pytest.mark.parametrize("name", ["../etc/passwd", "/abs", "a/../../b", "UPPER", ""])
def test_bad_entry_names_are_refused(tmp_path, name):
    with pytest.raises(ba.BackupError):
        _make(tmp_path, {name: b"x"})
    assert not os.path.exists(tmp_path / "x.ctembak.part")


def test_weak_password_is_refused(tmp_path):
    with pytest.raises(ba.BackupError, match="too weak"):
        _make(tmp_path, {"a": b"x"}, pw="short")


@pytest.mark.parametrize("pw,good", [
    ("short", False), ("alllowercaseletters", False), ("aaaaaaaaaaaaaaaaaaaaaaaaaaaa", False),
    ("Lower-and-UPPER-1", True), ("a long passphrase of plain words", True), (PW, True),
])
def test_password_rules(pw, good):
    assert (ba.password_problem(pw) is None) is good


def test_cli_round_trip(tmp_path, monkeypatch, capsys):
    src = tmp_path / "f"
    src.write_bytes(b"hello")
    out = str(tmp_path / "c.ctembak")
    monkeypatch.setenv(ba.PW_ENV, PW)
    assert ba.main(["pack", "--out", out, "--add", f"env/dotenv={src}", "--meta", "git_commit=abc"]) == 0
    monkeypatch.setenv(ba.PW_ENV, PW)
    assert ba.main(["verify", "--in", out]) == 0
    assert "env/dotenv  5 bytes" in capsys.readouterr().out
    monkeypatch.setenv(ba.PW_ENV, "Wrong-Password-Here-1")
    assert ba.main(["verify", "--in", out]) == 2
    monkeypatch.delenv(ba.PW_ENV, raising=False)
    assert ba.main(["verify", "--in", out]) == 2
