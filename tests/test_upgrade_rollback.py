"""install.sh --upgrade rolls back when the new version doesn't come up. From before 1.11.3 it must not go back to
code that can't read the envelope 1.11.4 has already rewritten stored secrets in."""
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not shutil.which("git") or not shutil.which("bash"), reason="needs git and bash")

V1 = 'WRITE_V2 = False\n'                          # before 1.11.3: no v2 reader
READS = '_V2 = "e2:"\nWRITE_V2 = False\n'          # 1.11.3
WRITES = '_V2 = "e2:"\nWRITE_V2 = True\n'          # 1.11.4


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _commit(repo, body):
    f = repo / "api" / "core" / "encryption.py"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "c")
    return _git(repo, "rev-parse", "HEAD")


def _rollback(repo, pre, post):
    fn = subprocess.run(["sed", "-n", "/^_reads_v2()/,/^}/p", str(ROOT / "install.sh")], check=True,
                        capture_output=True, text=True).stdout
    assert "rollback_rev()" in fn
    return subprocess.run(["bash", "-c", fn + '\nrollback_rev "$1" "$2"', "_", pre, post], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture()
def history(tmp_path):
    _git(tmp_path, "init", "-q")
    old = _commit(tmp_path, V1)
    mid = _commit(tmp_path, READS)
    new = _commit(tmp_path, WRITES)
    return tmp_path, old, mid, new


def test_upgrade_from_before_1_11_3_rolls_back_to_the_reader_not_the_start(history):
    repo, old, mid, new = history
    assert _rollback(repo, old, new) == mid


def test_ordinary_rollbacks_go_back_to_where_they_started(history):
    repo, old, mid, new = history
    assert _rollback(repo, mid, new) == mid    # 1.11.3 reads what 1.11.4 writes
    assert _rollback(repo, old, mid) == old    # 1.11.3 still writes the old envelope


def test_no_reader_in_between_means_no_code_rollback(tmp_path):
    _git(tmp_path, "init", "-q")
    old = _commit(tmp_path, V1)
    new = _commit(tmp_path, WRITES)
    assert _rollback(tmp_path, old, new) == ""
