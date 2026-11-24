"""Admin > Maintenance: backups, schedule and the job log. The host agent does the work; this only asks.

Every route is admin-only and browser-only (no API tokens). Downloading or deleting a backup, changing the schedule
and anything to do with restore also need a fresh step-up (password, plus TOTP when enrolled).
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import step_up
from api.auth.rbac import require_admin
from api.core.db import get_session
from api.core.security import _client_ip
from api.maintenance import agent_link
from api.maintenance.backup_archive import password_problem
from api.models.settings import AuditLog
from api.models.user import User

log = logging.getLogger("open-ctem.maintenance")
router = APIRouter(prefix="/api/v1/admin/maintenance", tags=["admin"])
STALE_HOURS = 26
SETUP_CMD = "sudo bash /data/docker/ctem/install.sh --maintenance-setup"


async def audit(db: AsyncSession, admin: User, request: Request, action: str, detail: str, rid: str | None = None) -> None:
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action=action, resource_type="maintenance",
                    resource_id=rid, detail=detail[:1000], ip_address=_client_ip(request)))
    await db.commit()


def admin_browser(request: Request, admin: User = Depends(require_admin)) -> User:
    step_up.browser_only(request)
    return admin


def ready_agent() -> dict:
    st = agent_link.status()
    if not st["installed"]:
        raise HTTPException(409, detail=f"The maintenance agent isn't set up on this server. Run: {SETUP_CMD}")
    if not st["alive"]:
        raise HTTPException(409, detail="The maintenance agent hasn't checked in for a while. "
                                        "Check it on the server: systemctl status ctem-maintenance.timer")
    return st


def queue(action: str, admin: User, fields: dict, secret: str | None = None) -> str:
    try:
        return agent_link.queue(action, admin.username, fields, secret)
    except (agent_link.AgentUnavailable, OSError) as exc:
        log.error("could not queue %s for the agent: %r", action, exc)
        raise HTTPException(409, detail=f"Could not reach the maintenance agent. Run: {SETUP_CMD}") from None


@router.get("")
async def overview(request: Request, admin: User = Depends(admin_browser)):
    st = agent_link.status()
    files = agent_link.backups()
    sched = agent_link.schedule()
    newest = max((b["modified"] for b in files), default=None)
    stale = sched["enabled"] and (newest is None or time.time() - newest > STALE_HOURS * 3600)
    from api.core.config import get_settings
    return {
        "agent": st, "setup_command": SETUP_CMD, "backups": files, "uploads": agent_link.uploads(),
        "jobs": agent_link.jobs(), "schedule": sched, "newest_backup": newest, "stale": stale,
        "step_up": {"until": step_up.active_until(request, admin), "needs": step_up.needs(admin)},
        "upload_max_bytes": get_settings().maintenance_upload_max_gb * 1024 ** 3,
    }


@router.post("/step-up")
async def confirm_identity(body: dict, request: Request, admin: User = Depends(admin_browser),
                           db: AsyncSession = Depends(get_session)):
    try:
        until = await step_up.verify(request, admin, body.get("password"), body.get("code"))
    except HTTPException as exc:
        if exc.status_code in (401, 429):
            await audit(db, admin, request, "maintenance_step_up_failed", exc.detail if isinstance(exc.detail, str) else "")
        raise
    await audit(db, admin, request, "maintenance_step_up", "confirmed identity for maintenance")
    return {"until": until}


@router.post("/backups")
async def create_backup(body: dict, request: Request, admin: User = Depends(admin_browser),
                        db: AsyncSession = Depends(get_session)):
    st = ready_agent()
    mode = body.get("password_mode")
    if mode not in ("default", "custom"):
        raise HTTPException(400, detail="Pick which password locks the backup.")
    secret = None
    if mode == "default":
        if st["default_password"] != "ok":
            raise HTTPException(400, detail="BACKUP_ENCRYPTION_PASSWORD in .env is missing or too weak. "
                                            "Fix it on the server or set a password for this backup.")
    else:
        pw, again = body.get("password"), body.get("confirm")
        if not isinstance(pw, str) or not isinstance(again, str) or len(pw) > 1024:
            raise HTTPException(400, detail="Type the password twice.")
        if pw != again:
            raise HTTPException(400, detail="The two passwords don't match.")
        problem = password_problem(pw)
        if problem:
            raise HTTPException(400, detail=f"Pick a stronger password: {problem}.")
        secret = pw
    jid = queue("backup", admin, {"password": mode}, secret)
    await audit(db, admin, request, "maintenance_backup_requested", f"backup queued, {mode} password", jid)
    return {"job": jid}


@router.get("/backups/{name}/download")
async def download_backup(name: str, request: Request, admin: User = Depends(admin_browser),
                          db: AsyncSession = Depends(get_session)):
    step_up.require(request, admin)
    try:
        path = agent_link.backup_path(name)
    except LookupError:
        raise HTTPException(404, detail="Backup not found") from None
    await audit(db, admin, request, "maintenance_backup_downloaded", f"downloaded {name}")
    return FileResponse(path, media_type="application/octet-stream", filename=name,
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.delete("/backups/{name}")
async def delete_backup(name: str, request: Request, admin: User = Depends(admin_browser),
                        db: AsyncSession = Depends(get_session)):
    step_up.require(request, admin)
    try:
        agent_link.backup_path(name)
    except LookupError:
        raise HTTPException(404, detail="Backup not found") from None
    ready_agent()
    jid = queue("delete", admin, {"file": name})
    await audit(db, admin, request, "maintenance_backup_delete_requested", f"delete {name}", jid)
    return {"job": jid}


@router.put("/schedule")
async def save_schedule(body: dict, request: Request, admin: User = Depends(admin_browser),
                        db: AsyncSession = Depends(get_session)):
    step_up.require(request, admin)
    st = ready_agent()
    en, hour, keep = body.get("enabled"), body.get("hour"), body.get("keep")
    if not isinstance(en, bool) or type(hour) is not int or type(keep) is not int or not 0 <= hour <= 23 or not 1 <= keep <= 90:
        raise HTTPException(400, detail="Pick an hour from 0 to 23 and keep between 1 and 90 backups.")
    if en and st["default_password"] != "ok":
        raise HTTPException(400, detail="Scheduled backups use BACKUP_ENCRYPTION_PASSWORD from .env, "
                                        "which is missing or too weak on this server.")
    jid = queue("schedule", admin, {"enabled": en, "hour": hour, "keep": keep})
    await audit(db, admin, request, "maintenance_schedule_changed",
                f"daily backups {'on' if en else 'off'} at {hour:02d}:00 UTC, keep {keep}", jid)
    return {"job": jid}


@router.get("/jobs/{jid}")
async def job_status(jid: str, admin: User = Depends(admin_browser)):
    j = agent_link.job(jid)
    if not j:
        raise HTTPException(404, detail="Job not found")
    return {"job": j, "log": agent_link.job_log(jid)}


@router.get("/database")
async def database(admin: User = Depends(require_admin)):
    """Table sizes, dead rows, last vacuum and analyze, and the last upkeep run (api/core/db_maintenance.py)."""
    from api.core.db_maintenance import status
    return await status()


@router.post("/database/run")
async def database_run(request: Request, admin: User = Depends(admin_browser), db: AsyncSession = Depends(get_session)):
    """Run the nightly upkeep now (VACUUM and ANALYZE where needed; no table is locked for more than a moment)."""
    from api.core.tasks_db import db_maintenance
    db_maintenance.delay(False)
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="maintenance.database_run",
                    resource_type="database", resource_id="postgres", detail="Started database upkeep", ip_address=_client_ip(request)))
    await db.commit()
    return {"queued": True}
