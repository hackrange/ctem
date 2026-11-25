#!/usr/bin/env python3
"""open-ctem maintenance agent: runs on the host as root and carries out what Admin > Maintenance asks for.
Author: Tim Rice <tim.j.rice@hackrange.com>
"""
# The app can only drop small JSON requests into run/spool/inbox. Everything in them is untrusted: names are
# matched against strict patterns, files are opened without following links, and the real work is install.sh.
# systemd starts this when the inbox fills (ctem-maintenance.path) and every 5 minutes (ctem-maintenance.timer).
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess  # nosec B404 - fixed argv lists, never a shell
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import agent_seal  # noqa: E402
from backup_archive import password_problem  # noqa: E402

VERSION = 1
ID_RE = re.compile(r"^[0-9a-f]{32}$")
REQ_RE = re.compile(r"^([0-9a-f]{32})\.json$")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.ctembak$")
USER_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
MAX_REQUEST = 16 * 1024
REQUEST_TTL = 30 * 60
UPLOAD_TTL = 24 * 3600
KEEP_JOBS = 200
ACTIONS = ("backup", "delete", "restore", "schedule")
_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
SPOOL_DIRS = ("inbox", "uploads", "tmp")


class Layout:
    def __init__(self, root: str):
        j = os.path.join
        self.root = os.path.realpath(root)
        self.run = j(self.root, "run")
        self.spool = j(self.run, "spool")
        self.inbox, self.uploads, self.tmp = j(self.spool, "inbox"), j(self.spool, "uploads"), j(self.spool, "tmp")
        self.state = j(self.run, "state")
        self.jobs = j(self.state, "jobs")
        self.backups = j(self.root, "backups")
        self.key, self.pub, self.lock = j(self.run, "agent.key"), j(self.state, "agent.pub"), j(self.run, ".agent.lock")
        self.env, self.installer = j(self.root, ".env"), j(self.root, "install.sh")


# ── small file helpers (every path here is inside a root-owned directory) ─────

def _dir(path: str, mode: int, dir_fd: int | None = None) -> None:
    # Ownership is set on what was opened, never by name, so a link put in the folder's place is refused
    try:
        os.mkdir(path, mode, dir_fd=dir_fd)
    except FileExistsError:
        pass
    try:
        fd = os.open(path, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError:
        raise SystemExit(f"{path} is a symlink or not a folder; refusing to use it") from None
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _write(path: str, data: bytes, mode: int = 0o640) -> None:
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        os.fchmod(f.fileno(), mode)
    os.replace(tmp, path)


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _unlink(path: str, dir_fd: int | None = None) -> None:
    try:
        os.unlink(path, dir_fd=dir_fd)
    except (FileNotFoundError, IsADirectoryError):
        pass


@contextmanager
def _spool(lay: Layout, name: str):
    """A spool folder as an open fd, reached through the spool without following links and checked to be the
    root-owned folder setup made. Everything in it is then listed, read, moved and removed relative to that fd."""
    top = os.open(lay.spool, _DIR_FLAGS)
    try:
        st = os.fstat(top)
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError(f"{lay.spool} is not the root-owned folder setup made; refusing to use it")
        try:
            fd = os.open(name, _DIR_FLAGS, dir_fd=top)
        except OSError:
            raise ValueError(f"spool/{name} is a symlink or not a folder; refusing to use it") from None
    finally:
        os.close(top)
    try:
        st = os.fstat(fd)
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, 0o770):
            raise ValueError(f"spool/{name} is not the folder setup made; refusing to use it")
        yield fd
    finally:
        os.close(fd)


def read_env(path: str) -> dict:
    out: dict = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.rstrip("\n").split("=", 1)
                    out[k.strip()] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
    except OSError:
        pass
    return out


def ui_restore_on(env: dict) -> bool:
    return env.get("MAINTENANCE_UI_RESTORE", "true").strip().lower() not in ("false", "0", "no", "off")


# ── setup and status ──────────────────────────────────────────────────────────

def setup(lay: Layout) -> None:
    # The app runs as uid 1000 in group root; it gets in through the group, so a host user 1000 gets nothing.
    # It may write in the spool's folders but never in the spool itself, so it can't put a link in their place.
    for path, mode in ((lay.run, 0o755), (lay.state, 0o750), (lay.jobs, 0o750), (lay.backups, 0o750), (lay.spool, 0o750)):
        _dir(path, mode)
    top = os.open(lay.spool, _DIR_FLAGS)
    try:
        for name in SPOOL_DIRS:
            _dir(name, 0o770, dir_fd=top)
    finally:
        os.close(top)
    if not os.path.isfile(lay.key):
        raw, _ = agent_seal.new_keypair()
        _write(lay.key, raw, 0o600)
    with open(lay.key, "rb") as f:
        _write(lay.pub, (agent_seal.public_from_private(f.read()) + "\n").encode())
    for name in os.listdir(lay.backups):
        p = os.path.join(lay.backups, name)
        if FILE_RE.match(name) and stat.S_ISREG(os.lstat(p).st_mode):
            os.chown(p, 0, 0)
            os.chmod(p, 0o640)


def _git_commit(lay: Layout) -> str:
    try:
        out = subprocess.run(["git", "-C", lay.root, "rev-parse", "HEAD"], capture_output=True, text=True,  # nosec B603 B607
                             timeout=10, env={"PATH": _PATH, "HOME": "/root"}).stdout.strip()
        return out if re.fullmatch(r"[0-9a-f]{40}", out) else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def heartbeat(lay: Layout, busy: str | None = None) -> None:
    env = read_env(lay.env)
    pw = env.get("BACKUP_ENCRYPTION_PASSWORD", "")
    fs = os.statvfs(lay.backups)
    data = {"version": VERSION, "time": int(time.time()), "busy": busy, "git_commit": _git_commit(lay),
            "default_password": ("weak" if password_problem(pw) else "ok") if pw else "missing",
            "ui_restore": ui_restore_on(env), "disk_free": fs.f_bavail * fs.f_frsize, "disk_total": fs.f_blocks * fs.f_frsize}
    _write(os.path.join(lay.state, "agent.json"), json.dumps(data).encode())


# ── requests ──────────────────────────────────────────────────────────────────

def _read_request(name: str, dir_fd: int) -> tuple[dict | None, str | None]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        _unlink(name, dir_fd)
        return None, "unreadable request"
    try:
        st = os.fstat(fd)
        raw = os.read(fd, MAX_REQUEST + 1) if stat.S_ISREG(st.st_mode) and st.st_size <= MAX_REQUEST else b""
    finally:
        os.close(fd)
        _unlink(name, dir_fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "malformed request"
    return (data, None) if isinstance(data, dict) else (None, "malformed request")


def take_requests(lay: Layout) -> list[tuple[str, dict | None, str | None]]:
    out = []
    with _spool(lay, "inbox") as fd:
        for name in sorted(os.listdir(fd)):
            m = REQ_RE.match(name)
            if not m:
                _unlink(name, fd)  # only finished requests are renamed in here, so anything else is junk
                continue
            data, err = _read_request(name, fd)
            out.append((m.group(1), data, err))
    return out


def _file(v) -> str:
    if not isinstance(v, str) or not FILE_RE.match(v):
        raise ValueError("bad backup file name")
    return v


def _sealed(v) -> str:
    if not isinstance(v, str) or not 0 < len(v) <= 2048:
        raise ValueError("missing password")
    return v


def validate(req: dict, now: int) -> dict:
    action, created, by = req.get("action"), req.get("created"), req.get("by")
    if action not in ACTIONS:
        raise ValueError("unknown action")
    if type(created) is not int or not now - REQUEST_TTL <= created <= now + 300:
        raise ValueError("the request expired before the agent picked it up")
    if not isinstance(by, str) or not USER_RE.match(by):
        raise ValueError("bad requester")
    out = {"action": action, "by": by}
    if action == "backup":
        if req.get("password") not in ("default", "custom"):
            raise ValueError("bad password choice")
        out["password"] = req["password"]
        if out["password"] == "custom":
            out["sealed"] = _sealed(req.get("sealed"))
    elif action == "delete":
        out["file"] = _file(req.get("file"))
    elif action == "restore":
        if req.get("source") not in ("backups", "uploads"):
            raise ValueError("bad restore source")
        out.update(source=req["source"], file=_file(req.get("file")), sealed=_sealed(req.get("sealed")))
    else:
        en, hour, keep = req.get("enabled"), req.get("hour"), req.get("keep")
        if not isinstance(en, bool) or type(hour) is not int or type(keep) is not int or not 0 <= hour <= 23 or not 1 <= keep <= 90:
            raise ValueError("bad schedule")
        out.update(enabled=en, hour=hour, keep=keep)
    return out


# ── jobs ──────────────────────────────────────────────────────────────────────

def _job_path(lay: Layout, jid: str, ext: str = "json") -> str:
    return os.path.join(lay.jobs, f"{jid}.{ext}")


def save_job(lay: Layout, job: dict) -> None:
    _write(_job_path(lay, job["id"]), json.dumps(job).encode())


def run_installer(lay: Layout, jid: str, args: list[str], extra_env: dict) -> tuple[int, str]:
    env = {"PATH": _PATH, "HOME": "/root", "LANG": "C.UTF-8", "TERM": "dumb", **extra_env}
    log_path = _job_path(lay, jid, "log")
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "wb") as log:
        p = subprocess.Popen(["/bin/bash", lay.installer, *args], cwd=lay.root, env=env,  # nosec B603
                             stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        while True:
            try:
                rc = p.wait(timeout=15)
                break
            except subprocess.TimeoutExpired:
                heartbeat(lay, busy=jid)
    with open(log_path, encoding="utf-8", errors="replace") as f:
        return rc, f.read()[-200_000:]


def _ready(text: str) -> list[str]:
    return [os.path.basename(m) for m in re.findall(r"Backup ready: (\S+\.ctembak)", text)]


def _failure(text: str, fallback: str) -> str:
    lines = [ln.strip()[2:].strip() for ln in text.splitlines() if ln.strip().startswith("xx ")]
    return (lines[-1] if lines else fallback)[:300]


def catalog_add(lay: Layout, name: str, **info) -> None:
    path = os.path.join(lay.state, "catalog.json")
    cat = _load(path)
    cat[name] = {**info, "added": int(time.time())}
    _write(path, json.dumps(cat).encode())


def catalog_prune(lay: Layout) -> dict:
    path = os.path.join(lay.state, "catalog.json")
    cat = _load(path)
    keep = {k: v for k, v in cat.items() if FILE_RE.match(k) and os.path.isfile(os.path.join(lay.backups, k))}
    if keep != cat:
        _write(path, json.dumps(keep).encode())
    return keep


def backup_path(lay: Layout, name: str) -> str:
    p = os.path.join(lay.backups, _file(name))
    try:
        if stat.S_ISREG(os.lstat(p).st_mode):
            return p
    except FileNotFoundError:
        pass
    raise ValueError("that backup is not on this server")


def adopt_upload(lay: Layout, name: str) -> str:
    """Move an uploaded file into the root-owned backups folder before anything reads it."""
    dest = os.path.join(lay.backups, _file(name))
    if os.path.lexists(dest):
        raise ValueError("a backup with that name already exists")
    with _spool(lay, "uploads") as fd:
        try:
            if not stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                raise ValueError("the upload is not a regular file")
        except FileNotFoundError:
            raise ValueError("the upload is gone; upload it again") from None
        os.rename(name, dest, src_dir_fd=fd)
    if not stat.S_ISREG(os.lstat(dest).st_mode):  # swapped between the check and the move
        _unlink(dest)
        raise ValueError("the upload is not a regular file")
    os.chown(dest, 0, 0, follow_symlinks=False)
    os.chmod(dest, 0o640)
    return dest


def do_backup(lay: Layout, job: dict, req: dict, key: bytes, kind: str) -> None:
    env = {}
    if req["password"] == "custom":
        env["CTEM_BACKUP_PASSWORD"] = agent_seal.unseal(key, req["sealed"], f"{job['id']}:backup".encode())
    rc, text = run_installer(lay, job["id"], ["--backup"], env)
    made = _ready(text)
    if rc != 0 or not made:
        raise RuntimeError(_failure(text, "The backup failed. See the log."))
    catalog_add(lay, made[-1], kind=kind, by=job["by"], lock=req["password"])
    job.update(result=made[-1], message=f"Backup ready: {made[-1]}")


def do_restore(lay: Layout, job: dict, req: dict, key: bytes) -> None:
    if not ui_restore_on(read_env(lay.env)):
        raise ValueError("restores from the web page are turned off on this server (MAINTENANCE_UI_RESTORE)")
    pw = agent_seal.unseal(key, req["sealed"], f"{job['id']}:restore".encode())
    path = adopt_upload(lay, req["file"]) if req["source"] == "uploads" else backup_path(lay, req["file"])
    if req["source"] == "uploads":
        catalog_add(lay, req["file"], kind="uploaded", by=job["by"], lock="custom")
    rc, text = run_installer(lay, job["id"], ["--restore", path],
                             {"CTEM_BACKUP_PASSWORD": pw, "CTEM_RESTORE_CONFIRM": "RESTORE", "CTEM_RESTORE_FROM_UI": "1"})
    for name in _ready(text):
        catalog_add(lay, name, kind="safety", by=job["by"], lock="default")
    if rc != 0:
        raise RuntimeError(_failure(text, "The restore failed. See the log."))
    job["message"] = f"Restored from {req['file']}"


def handle(lay: Layout, jid: str, raw: dict | None, err: str | None, key: bytes) -> None:
    if os.path.exists(_job_path(lay, jid)):
        return  # a replayed request id
    now = int(time.time())
    job = {"id": jid, "action": "unknown", "by": "", "status": "running", "started": now, "finished": None, "message": ""}
    try:
        if err:
            raise ValueError(err)
        req = validate(raw or {}, now)
        job.update(action=req["action"], by=req["by"], file=req.get("file"))
        save_job(lay, job)
        if req["action"] == "backup":
            do_backup(lay, job, req, key, "manual")
        elif req["action"] == "restore":
            do_restore(lay, job, req, key)
        elif req["action"] == "delete":
            os.unlink(backup_path(lay, req["file"]))
            job["message"] = f"Deleted {req['file']}"
        else:
            sched = {k: req[k] for k in ("enabled", "hour", "keep")} | {"by": req["by"], "updated": now}
            _write(os.path.join(lay.state, "schedule.json"), json.dumps(sched).encode())
            job["message"] = "Schedule saved"
        job["status"] = "ok"
    except (ValueError, RuntimeError, agent_seal.SealError) as exc:
        job.update(status="failed", message=str(exc)[:300])
    except Exception as exc:  # noqa: BLE001 - never leave a job stuck on "running"
        job.update(status="failed", message=f"unexpected error ({type(exc).__name__}); see the agent's journal")
        print(f"job {jid}: {exc!r}", file=sys.stderr)
    job["finished"] = int(time.time())
    save_job(lay, job)


# ── schedule, retention, housekeeping ─────────────────────────────────────────

def scheduled(lay: Layout, key: bytes) -> None:
    sched = _load(os.path.join(lay.state, "schedule.json"))
    if not sched.get("enabled") or type(sched.get("hour")) is not int:
        return
    now = datetime.now(timezone.utc)
    if now.hour < sched["hour"]:
        return
    st_path = os.path.join(lay.state, "schedule_state.json")
    st = _load(st_path)
    today, ts = now.strftime("%Y-%m-%d"), int(now.timestamp())
    if st.get("date") != today:
        st = {"date": today, "attempts": 0, "ok": False, "last": 0}
    if st["ok"] or st["attempts"] >= 3 or ts - st["last"] < 3600:
        return
    job = {"id": uuid.uuid4().hex, "action": "backup", "by": "schedule", "status": "running", "started": ts,
           "finished": None, "message": ""}
    save_job(lay, job)
    try:
        do_backup(lay, job, {"password": "default"}, key, "scheduled")  # nosec B105 - the lock type, not a password
        job["status"] = "ok"
        prune_scheduled(lay, int(sched.get("keep") or 7))
    except (RuntimeError, ValueError) as exc:
        job.update(status="failed", message=str(exc)[:300])
    job["finished"] = int(time.time())
    save_job(lay, job)
    st.update(attempts=st["attempts"] + 1, ok=job["status"] == "ok", last=ts)
    _write(st_path, json.dumps(st).encode())


def prune_scheduled(lay: Layout, keep: int) -> None:
    cat = catalog_prune(lay)
    mine = sorted((k for k, v in cat.items() if v.get("kind") == "scheduled"), key=lambda k: cat[k].get("added", 0), reverse=True)
    for name in mine[max(1, keep):]:
        try:
            os.unlink(backup_path(lay, name))
        except ValueError:
            pass
    catalog_prune(lay)


def housekeeping(lay: Layout) -> None:
    now = time.time()
    for folder, ttl in (("uploads", UPLOAD_TTL), ("tmp", 6 * 3600)):
        with _spool(lay, folder) as fd:
            for name in os.listdir(fd):
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(st.st_mode) and now - st.st_mtime > ttl:
                    _unlink(name, fd)
    jobs = sorted((n for n in os.listdir(lay.jobs) if n.endswith(".json") and ID_RE.match(n[:-5])),
                  key=lambda n: os.lstat(os.path.join(lay.jobs, n)).st_mtime, reverse=True)
    for name in jobs[KEEP_JOBS:]:
        _unlink(os.path.join(lay.jobs, name))
        _unlink(os.path.join(lay.jobs, name[:-5] + ".log"))
    catalog_prune(lay)


def run(lay: Layout) -> None:
    setup(lay)
    with open(lay.lock, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        heartbeat(lay)
        with open(lay.key, "rb") as f:
            key = f.read()
        for _ in range(50):  # new requests can land while a long job runs
            batch = take_requests(lay)
            if not batch:
                break
            for jid, raw, err in batch:
                handle(lay, jid, raw, err, key)
        scheduled(lay, key)
        housekeeping(lay)
        heartbeat(lay)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="open-ctem maintenance agent (run by systemd as root)")
    ap.add_argument("command", choices=["run", "setup"])
    ap.add_argument("--root", required=True, help="the open-ctem checkout, e.g. /data/docker/ctem")
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("run this as root", file=sys.stderr)
        return 2
    lay = Layout(a.root)
    if not os.path.isfile(lay.installer):
        print(f"no install.sh in {lay.root}", file=sys.stderr)
        return 2
    setup(lay) if a.command == "setup" else run(lay)
    return 0


if __name__ == "__main__":
    sys.exit(main())
