"""Host maintenance agent: requests in, jobs out, with hostile input from the app side refused."""
from __future__ import annotations

import json
import os
import time

import pytest

from api.maintenance import agent_link, agent_seal
from api.maintenance import host_agent as ha

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="the agent chowns to root")

# A stand-in install.sh: records how it was called and pretends to make a backup
STUB = r"""#!/bin/bash
echo "args: $*" >> "$(dirname "$0")/calls.log"
echo "pw: ${CTEM_BACKUP_PASSWORD:-none} confirm: ${CTEM_RESTORE_CONFIRM:-none} ui: ${CTEM_RESTORE_FROM_UI:-none}" >> "$(dirname "$0")/calls.log"
if [[ "$1" == --backup ]]; then
  f="$(dirname "$0")/backups/ctem-server001-$(date -u +%Y%m%d-%H%M%S)-$RANDOM.ctembak"
  printf 'CTEMBAK1' > "$f"; echo "  ok  Backup ready: $f (4K)"
fi
if [[ "$1" == --restore && -f "$(dirname "$0")/fail" ]]; then echo "  xx  Loading the database failed."; exit 1; fi
exit 0
"""


@pytest.fixture
def box(tmp_path, monkeypatch):
    root = tmp_path / "ctem"
    root.mkdir()
    (root / "install.sh").write_text(STUB)
    (root / ".env").write_text("BACKUP_ENCRYPTION_PASSWORD=Correct-Horse-Battery-9-example\n")
    lay = ha.Layout(str(root))
    ha.setup(lay)
    # the app sees the same folders through its mounts
    srv = tmp_path / "srv"
    srv.mkdir()
    os.symlink(lay.spool, srv / "spool")
    os.symlink(lay.state, srv / "state")
    os.symlink(lay.backups, srv / "backups")
    from api.core.config import get_settings
    monkeypatch.setattr(get_settings(), "maintenance_dir", str(srv))
    return lay


def _calls(lay) -> str:
    p = os.path.join(lay.root, "calls.log")
    return open(p).read() if os.path.exists(p) else ""


def test_setup_layout_and_permissions(box):
    assert oct(os.stat(box.inbox).st_mode & 0o777) == "0o770"
    assert oct(os.stat(box.state).st_mode & 0o777) == "0o750"
    assert oct(os.stat(box.key).st_mode & 0o777) == "0o600"
    assert open(box.pub).read().strip() == agent_seal.public_from_private(open(box.key, "rb").read())
    ha.setup(box)   # idempotent, same key
    assert open(box.pub).read().strip() == agent_seal.public_from_private(open(box.key, "rb").read())


def test_backup_round_trip_through_the_app_side(box):
    ha.heartbeat(box)
    assert agent_link.status()["installed"] and agent_link.status()["default_password"] == "ok"
    jid = agent_link.queue("backup", "admin", {"password": "custom"}, "My-Own-Backup-Pass-2026")
    assert agent_link.job(jid)["status"] == "queued"
    raw = open(os.path.join(box.inbox, f"{jid}.json")).read()
    assert "My-Own-Backup-Pass" not in raw   # sealed, never plain
    ha.run(box)
    j = agent_link.job(jid)
    assert j["status"] == "ok" and j["result"].endswith(".ctembak")
    assert "pw: My-Own-Backup-Pass-2026" in _calls(box)
    b = agent_link.backups()
    assert b[0]["kind"] == "manual" and b[0]["password"] == "custom" and b[0]["by"] == "admin"
    assert not os.listdir(box.inbox)


def test_replayed_request_id_runs_once(box):
    ha.heartbeat(box)
    jid = agent_link.queue("backup", "admin", {"password": "default"})
    saved = open(os.path.join(box.inbox, f"{jid}.json")).read()
    ha.run(box)
    open(os.path.join(box.inbox, f"{jid}.json"), "w").write(saved)
    ha.run(box)
    assert _calls(box).count("--backup") == 1


def test_sealed_password_cannot_move_to_another_request(box):
    ha.heartbeat(box)
    jid = agent_link.queue("backup", "admin", {"password": "custom"}, "My-Own-Backup-Pass-2026")
    req = json.load(open(os.path.join(box.inbox, f"{jid}.json")))
    os.unlink(os.path.join(box.inbox, f"{jid}.json"))
    other = "f" * 32
    req.update(action="restore", source="backups", file="x.ctembak")
    open(os.path.join(box.inbox, f"{other}.json"), "w").write(json.dumps(req))
    open(os.path.join(box.backups, "x.ctembak"), "w").write("CTEMBAK1")
    ha.run(box)
    assert agent_link.job(other)["status"] == "failed" and "--restore" not in _calls(box)


@pytest.mark.parametrize("req,why", [
    ({"action": "rm -rf"}, "unknown action"),
    ({"action": "delete", "file": "../../etc/passwd"}, "bad backup file name"),
    ({"action": "delete", "file": "x.ctembak", "created": 1}, "expired"),
    ({"action": "schedule", "enabled": True, "hour": 25, "keep": 7}, "bad schedule"),
    ({"action": "backup", "password": "custom"}, "missing password"),
    ({"action": "restore", "source": "/etc", "file": "x.ctembak", "sealed": "x"}, "bad restore source"),
    ({"action": "delete", "file": "x.ctembak", "by": "a\nb"}, "bad requester"),
])
def test_bad_requests_fail_closed(box, req, why):
    full = {"by": "admin", "created": int(time.time()), **req}
    jid = "a" * 32
    open(os.path.join(box.inbox, f"{jid}.json"), "w").write(json.dumps(full))
    ha.run(box)
    j = agent_link.job(jid)
    assert j["status"] == "failed" and why in j["message"] and _calls(box) == ""


def test_junk_and_links_in_the_inbox_are_removed_unread(box, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"action": "delete", "file": "x.ctembak", "by": "a", "created": int(time.time())}))
    os.symlink(secret, os.path.join(box.inbox, "b" * 32 + ".json"))
    os.mkfifo(os.path.join(box.inbox, "c" * 32 + ".json"))
    open(os.path.join(box.inbox, "notes.txt"), "w").write("hi")
    open(os.path.join(box.inbox, "d" * 32 + ".json"), "w").write("x" * (ha.MAX_REQUEST + 10))
    ha.run(box)
    assert os.listdir(box.inbox) == [] and secret.exists()
    assert agent_link.job("b" * 32)["status"] == "failed"
    assert agent_link.job("d" * 32)["status"] == "failed"


def test_delete_only_touches_backups(box):
    ha.heartbeat(box)
    open(os.path.join(box.backups, "keep.ctembak"), "w").write("CTEMBAK1")
    os.symlink("/etc/hostname", os.path.join(box.backups, "link.ctembak"))
    gone = agent_link.queue("delete", "admin", {"file": "keep.ctembak"})
    link = agent_link.queue("delete", "admin", {"file": "link.ctembak"})
    ha.run(box)
    assert agent_link.job(gone)["status"] == "ok" and not os.path.exists(os.path.join(box.backups, "keep.ctembak"))
    assert agent_link.job(link)["status"] == "failed" and os.path.exists("/etc/hostname")


def test_restore_from_upload_moves_it_first_and_passes_the_password(box):
    ha.heartbeat(box)
    name = "upload-20261123-101500-0123abcd.ctembak"
    open(os.path.join(box.uploads, name), "w").write("CTEMBAK1")
    jid = agent_link.queue("restore", "admin", {"source": "uploads", "file": name}, "The-Backup-Pass-2026!")
    ha.run(box)
    assert agent_link.job(jid)["status"] == "ok"
    assert not os.path.exists(os.path.join(box.uploads, name))
    moved = os.path.join(box.backups, name)
    assert os.stat(moved).st_uid == 0 and oct(os.stat(moved).st_mode & 0o777) == "0o640"
    calls = _calls(box)
    assert f"--restore {moved}" in calls and "pw: The-Backup-Pass-2026! confirm: RESTORE ui: 1" in calls


def test_restore_failure_and_the_off_switch(box):
    ha.heartbeat(box)
    open(os.path.join(box.backups, "x.ctembak"), "w").write("CTEMBAK1")
    open(os.path.join(box.root, "fail"), "w").write("")
    jid = agent_link.queue("restore", "admin", {"source": "backups", "file": "x.ctembak"}, "The-Backup-Pass-2026!")
    ha.run(box)
    assert agent_link.job(jid)["status"] == "failed" and agent_link.job(jid)["message"] == "Loading the database failed."
    with open(box.env, "a") as f:
        f.write("MAINTENANCE_UI_RESTORE=false\n")
    jid = agent_link.queue("restore", "admin", {"source": "backups", "file": "x.ctembak"}, "The-Backup-Pass-2026!")
    ha.run(box)
    assert "turned off" in agent_link.job(jid)["message"] and _calls(box).count("--restore") == 1


def test_schedule_runs_once_a_day_and_keeps_the_newest(box, monkeypatch):
    ha.heartbeat(box)
    jid = agent_link.queue("schedule", "admin", {"enabled": True, "hour": 0, "keep": 2})
    ha.run(box)
    assert agent_link.job(jid)["status"] == "ok" and agent_link.schedule()["enabled"]
    assert _calls(box).count("--backup") == 1
    ha.run(box)
    assert _calls(box).count("--backup") == 1   # once a day
    for _ in range(3):   # pretend more days went by
        os.unlink(os.path.join(box.state, "schedule_state.json"))
        time.sleep(0.01)
        ha.run(box)
    scheduled = [b for b in agent_link.backups() if b["kind"] == "scheduled"]
    assert len(scheduled) == 2


def test_stale_uploads_are_cleaned_up(box):
    old = os.path.join(box.uploads, "upload-20200101-000000-00000000.ctembak")
    open(old, "w").write("x")
    os.utime(old, (time.time() - ha.UPLOAD_TTL - 10,) * 2)
    ha.run(box)
    assert not os.path.exists(old)


def test_seal_is_bound_to_its_context():
    raw, pub = agent_seal.new_keypair()
    tok = agent_seal.seal(pub, "pw-123", b"a:backup")
    assert agent_seal.unseal(raw, tok, b"a:backup") == "pw-123"
    for ctx in (b"b:backup", b"a:restore"):
        with pytest.raises(agent_seal.SealError):
            agent_seal.unseal(raw, tok, ctx)
    other, _ = agent_seal.new_keypair()
    with pytest.raises(agent_seal.SealError):
        agent_seal.unseal(other, tok, b"a:backup")
