"""Admin > Maintenance > Restore: upload a backup, check it opens, and ask the host agent to restore it.

The restore itself is install.sh --restore run by the agent as root, exactly as on the command line, except that
a restore started here keeps this server's docker-compose.override.yml and nginx.conf.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from api.auth import step_up
from api.core.config import get_settings
from api.core.db import get_session
from api.maintenance import agent_link, backup_archive
from api.models.user import User
from api.routes.admin_maintenance import admin_browser, audit, queue, ready_agent

router = APIRouter(prefix="/api/v1/admin/maintenance", tags=["admin"])
_one_at_a_time = asyncio.Semaphore(1)   # each password guess costs ~128 MB of scrypt
_SPARE = 2 * 1024 ** 3
_MANIFEST_MAX = 256 * 1024
_SHOWN = ("created_utc", "host", "git_commit", "app_version", "timescaledb", "db_name")


def _source_path(source: object, name: object) -> str:
    try:
        if source == "backups":
            return agent_link.backup_path(name)          # type: ignore[arg-type]
        if source == "uploads":
            return agent_link.upload_path(name)          # type: ignore[arg-type]
    except LookupError:
        pass
    raise HTTPException(404, detail="Backup not found")


def _password(body: dict) -> str:
    pw = body.get("password")
    if not isinstance(pw, str) or not pw or len(pw) > 1024:
        raise HTTPException(400, detail="Enter the backup's password.")
    return pw


def _read_manifest(path: str, pw: str) -> dict:
    for name, blocks in backup_archive.entries(path, pw):
        if name != "manifest.json":
            break
        data = b""
        for b in blocks:
            data += b
            if len(data) > _MANIFEST_MAX:
                break
        else:
            m = json.loads(data)
            if isinstance(m, dict) and m.get("format") == backup_archive.FORMAT:
                return m
        break
    raise backup_archive.BackupError("not an open-ctem backup")


async def _manifest(path: str, pw: str) -> dict:
    async with _one_at_a_time:
        try:
            return await run_in_threadpool(_read_manifest, path, pw)
        except (backup_archive.BackupError, ValueError, OSError):
            raise HTTPException(400, detail="That password doesn't open this backup, or the file is damaged.") from None


@router.post("/uploads")
async def upload_backup(request: Request, admin: User = Depends(admin_browser), db: AsyncSession = Depends(get_session)):
    ready_agent()
    limit = get_settings().maintenance_upload_max_gb * 1024 ** 3
    try:
        size = int(request.headers.get("content-length") or 0)
    except ValueError:
        size = 0
    if size > limit:
        raise HTTPException(413, detail=f"That file is bigger than the {limit // 1024 ** 3} GB upload limit. "
                                        "Copy it into the server's backups folder instead.")
    if size and size + _SPARE > shutil.disk_usage(agent_link.spool("uploads")).free:
        raise HTTPException(507, detail="Not enough free disk space on the server for that upload.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"upload-{stamp}-{secrets.token_hex(4)}.ctembak"
    tmp = os.path.join(agent_link.spool("tmp"), f"{name}.part")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    total, head = 0, b""
    try:
        with os.fdopen(fd, "wb") as f:
            async for chunk in request.stream():
                total += len(chunk)
                if total > limit:
                    raise HTTPException(413, detail="That file is bigger than the upload limit.")
                if len(head) < len(backup_archive.MAGIC):
                    head += chunk[:len(backup_archive.MAGIC) - len(head)]
                    if len(head) == len(backup_archive.MAGIC) and head != backup_archive.MAGIC:
                        raise HTTPException(400, detail="That is not an open-ctem backup (.ctembak) file.")
                await run_in_threadpool(f.write, chunk)
        if head != backup_archive.MAGIC:
            raise HTTPException(400, detail="That is not an open-ctem backup (.ctembak) file.")
        os.rename(tmp, os.path.join(agent_link.spool("uploads"), name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    await audit(db, admin, request, "maintenance_backup_uploaded", f"uploaded {name} ({total} bytes)")
    return {"name": name, "size": total}


@router.delete("/uploads/{name}")
async def delete_upload(name: str, request: Request, admin: User = Depends(admin_browser),
                        db: AsyncSession = Depends(get_session)):
    try:
        os.unlink(agent_link.upload_path(name))
    except (LookupError, FileNotFoundError):
        raise HTTPException(404, detail="Upload not found") from None
    await audit(db, admin, request, "maintenance_upload_deleted", f"deleted upload {name}")
    return {"deleted": True}


@router.post("/restore/check")
async def check_backup(body: dict, request: Request, admin: User = Depends(admin_browser),
                       db: AsyncSession = Depends(get_session)):
    """Open the backup with its password and show what's inside, without changing anything."""
    step_up.require(request, admin)
    path = _source_path(body.get("source"), body.get("name"))
    try:
        m = await _manifest(path, _password(body))
    except HTTPException:
        await audit(db, admin, request, "maintenance_restore_check_failed", f"could not open {body.get('name')}")
        raise
    here = agent_link.status()["git_commit"]
    shown = {k: str(m.get(k, ""))[:200] for k in _SHOWN}
    return {"manifest": shown, "server_commit": here,
            "same_commit": bool(here) and shown["git_commit"] == here}


@router.post("/restore")
async def start_restore(body: dict, request: Request, admin: User = Depends(admin_browser),
                        db: AsyncSession = Depends(get_session)):
    step_up.require(request, admin)
    st = ready_agent()
    if not st["ui_restore"]:
        raise HTTPException(403, detail="Restores from this page are turned off on this server (MAINTENANCE_UI_RESTORE). "
                                        "Use install.sh --restore on the server.")
    if body.get("confirm") != "RESTORE":
        raise HTTPException(400, detail="Type RESTORE to confirm.")
    if st["busy"]:
        raise HTTPException(409, detail="The agent is busy with another job. Try again when it finishes.")
    source, name = body.get("source"), body.get("name")
    path = _source_path(source, name)
    pw = _password(body)
    await _manifest(path, pw)   # a wrong password fails here, not halfway through a restore
    jid = queue("restore", admin, {"source": source, "file": name}, pw)
    await audit(db, admin, request, "maintenance_restore_requested", f"restore from {name} ({source})", jid)
    return {"job": jid}
