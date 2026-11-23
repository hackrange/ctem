"""App side of the host maintenance agent: read what it reports, list backups, queue requests for it.

The agent owns run/state and backups (both mounted read-only here). The app can write only to run/spool, and only
whole files: a request is written to spool/tmp and renamed into spool/inbox, which wakes the agent.
Author: Tim Rice <tim.j.rice@hackrange.com>
"""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import time

from api.core.config import get_settings
from api.maintenance import agent_seal

FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.ctembak$")
UPLOAD_RE = re.compile(r"^upload-\d{8}-\d{6}-[0-9a-f]{8}\.ctembak$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
ALIVE_SECONDS = 15 * 60
KINDS = {"manual", "scheduled", "safety", "uploaded"}


class AgentUnavailable(Exception):
    pass


def _p(*parts: str) -> str:
    return os.path.join(get_settings().maintenance_dir, *parts)


def spool(name: str) -> str:
    return _p("spool", name)


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.loads(f.read(2_000_000))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _int(v) -> int | None:
    return v if type(v) is int else None


def status() -> dict:
    hb = _load(_p("state", "agent.json"))
    pub = _public_key()
    writable = all(os.access(spool(d), os.W_OK | os.X_OK) for d in ("inbox", "uploads", "tmp"))
    seen = _int(hb.get("time"))
    busy = hb.get("busy") if isinstance(hb.get("busy"), str) and ID_RE.match(hb["busy"]) else None
    return {
        "installed": bool(hb) and bool(pub) and writable,
        "alive": seen is not None and time.time() - seen < ALIVE_SECONDS,
        "heartbeat": seen, "busy": busy,
        "git_commit": hb.get("git_commit") if isinstance(hb.get("git_commit"), str) else "",
        "default_password": hb.get("default_password") if hb.get("default_password") in ("ok", "weak", "missing") else "unknown",
        "ui_restore": hb.get("ui_restore") is True and get_settings().maintenance_ui_restore,
        "disk_free": _int(hb.get("disk_free")), "disk_total": _int(hb.get("disk_total")),
    }


def _public_key() -> str:
    try:
        with open(_p("state", "agent.pub"), encoding="ascii") as f:
            return f.read(200).strip()
    except (OSError, UnicodeDecodeError):
        return ""


def _regular(path: str) -> os.stat_result | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def _files(folder: str, pattern: re.Pattern) -> list[tuple[str, os.stat_result]]:
    try:
        names = os.listdir(folder)
    except OSError:
        return []
    out = []
    for name in names:
        st = _regular(os.path.join(folder, name)) if pattern.match(name) else None
        if st:
            out.append((name, st))
    return sorted(out, key=lambda x: x[1].st_mtime, reverse=True)


def backups() -> list[dict]:
    cat = _load(_p("state", "catalog.json"))
    out = []
    for name, st in _files(_p("backups"), FILE_RE):
        info = cat.get(name) if isinstance(cat.get(name), dict) else {}
        kind = info.get("kind") if info.get("kind") in KINDS else "other"
        by = info.get("by") if isinstance(info.get("by"), str) else ""
        pw = info.get("lock") if info.get("lock") in ("default", "custom") else "unknown"
        out.append({"name": name, "size": st.st_size, "modified": int(st.st_mtime), "kind": kind, "by": by[:128], "password": pw})
    return out


def uploads() -> list[dict]:
    return [{"name": n, "size": st.st_size, "modified": int(st.st_mtime)} for n, st in _files(spool("uploads"), UPLOAD_RE)]


def backup_path(name: str) -> str:
    """Path of a backup by name, or LookupError. Names never become paths without the pattern and the folder check."""
    if not isinstance(name, str) or not FILE_RE.match(name):
        raise LookupError(name)
    path = _p("backups", name)
    if not _regular(path):
        raise LookupError(name)
    return path


def upload_path(name: str) -> str:
    if not isinstance(name, str) or not UPLOAD_RE.match(name):
        raise LookupError(name)
    path = os.path.join(spool("uploads"), name)
    if not _regular(path):
        raise LookupError(name)
    return path


def schedule() -> dict:
    s = _load(_p("state", "schedule.json"))
    st = _load(_p("state", "schedule_state.json"))
    return {"enabled": s.get("enabled") is True, "hour": _int(s.get("hour")) if _int(s.get("hour")) is not None else 2,
            "keep": _int(s.get("keep")) or 7, "last_attempt": _int(st.get("last")), "last_ok": st.get("ok") is True,
            "attempts_today": _int(st.get("attempts")) or 0}


def _clean_job(j: dict) -> dict | None:
    if not isinstance(j.get("id"), str) or not ID_RE.match(j["id"]):
        return None
    pick = {k: j.get(k) for k in ("id", "action", "by", "status", "message", "file", "result")}
    for k, v in list(pick.items()):
        pick[k] = v[:300] if isinstance(v, str) else None
    pick.update(started=_int(j.get("started")), finished=_int(j.get("finished")))
    return pick


def jobs(limit: int = 25) -> list[dict]:
    folder = _p("state", "jobs")
    found = []
    for name, st in _files(folder, re.compile(r"^[0-9a-f]{32}\.json$"))[:limit]:
        j = _clean_job(_load(os.path.join(folder, name)))
        if j:
            found.append(j)
    return sorted(found, key=lambda j: j["started"] or 0, reverse=True)


def job(jid: str) -> dict | None:
    if not ID_RE.match(jid or ""):
        return None
    j = _clean_job(_load(_p("state", "jobs", f"{jid}.json")))
    if j:
        return j
    if _regular(os.path.join(spool("inbox"), f"{jid}.json")):
        return {"id": jid, "status": "queued"}
    return None


def job_log(jid: str, max_bytes: int = 64 * 1024) -> str:
    if not ID_RE.match(jid or ""):
        return ""
    path = _p("state", "jobs", f"{jid}.log")
    st = _regular(path)
    if not st:
        return ""
    with open(path, "rb") as f:
        f.seek(max(0, st.st_size - max_bytes))
        text = f.read().decode("utf-8", errors="replace")
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


def queue(action: str, by: str, fields: dict, secret: str | None = None) -> str:
    """Hand a request to the agent and return its job id."""
    st = status()
    if not st["installed"]:
        raise AgentUnavailable("not installed")
    jid = secrets.token_hex(16)
    req = {"action": action, "by": by[:128], "created": int(time.time()), **fields}
    if secret is not None:
        req["sealed"] = agent_seal.seal(_public_key(), secret, f"{jid}:{action}".encode())
    tmp = os.path.join(spool("tmp"), f"{jid}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(req).encode())
        os.rename(tmp, os.path.join(spool("inbox"), f"{jid}.json"))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return jid
