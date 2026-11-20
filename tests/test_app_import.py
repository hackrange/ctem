"""The app must import cleanly in a fresh interpreter (no conftest model preloading)."""
import os
import subprocess
import sys


def test_app_imports_in_clean_process():
    env = dict(os.environ)
    code = "import api.main; from sqlalchemy.orm import configure_mappers; configure_mappers()"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
