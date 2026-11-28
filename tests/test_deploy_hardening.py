"""Deployment hardening: the load-balancer listener believes forwarded client IPs only from the configured load
balancers, the app image's code is read-only to the user it runs as, and the collector image is on a patched Python."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "docker" / "nginx-lb-trusted.sh"


def _lb_server() -> str:
    conf = (ROOT / "docker" / "nginx.conf").read_text()
    return conf[conf.index("listen 8085;"):]


def test_the_lb_listener_trusts_only_the_written_list():
    lb = _lb_server()
    assert "include /etc/nginx/lb_trusted*.conf;" in lb
    assert "set_real_ip_from" not in (ROOT / "docker" / "nginx.conf").read_text()
    assert "real_ip_recursive off;" in lb
    compose = (ROOT / "docker" / "docker-compose.yml").read_text()
    assert "./nginx-lb-trusted.sh:/docker-entrypoint.d/15-lb-trusted.sh:ro" in compose
    assert "LB_TRUSTED_IPS: ${LB_TRUSTED_IPS:-}" in compose and "LB_BIND_IP: ${LB_BIND_IP:-}" in compose


def _run(tmp_path, value: str | None, bind: str | None = None) -> tuple[str, str]:
    script = tmp_path / "lb.sh"
    script.write_text(SCRIPT.read_text().replace("/etc/nginx/lb_trusted.conf", str(tmp_path / "out.conf")))
    env = {"PATH": "/usr/bin:/bin"}
    if value is not None:
        env["LB_TRUSTED_IPS"] = value
    if bind is not None:
        env["LB_BIND_IP"] = bind
    r = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, check=True)
    return (tmp_path / "out.conf").read_text(), r.stderr


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
def test_the_trust_list_takes_addresses_and_refuses_catch_alls(tmp_path):
    out, _ = _run(tmp_path, "10.0.0.1, 10.0.0.2,fd00::1/128")
    assert out.splitlines() == ["set_real_ip_from 10.0.0.1;", "set_real_ip_from 10.0.0.2;", "set_real_ip_from fd00::1/128;"]
    out, err = _run(tmp_path, "0.0.0.0/0,::/0,10.0.0.1;evil,10.0.0.3")
    assert out.splitlines() == ["set_real_ip_from 10.0.0.3;"] and "catch-all" in err and "ignoring" in err
    out, err = _run(tmp_path, None)
    assert out == "" and "trusts no forwarded address" in err
    # an existing load-balanced install that hasn't set the list yet trusts only its bind network, and is warned
    out, err = _run(tmp_path, None, bind="10.0.0.9")
    assert out.splitlines() == ["set_real_ip_from 10.0.0.0/24;"] and "WARNING" in err
    out, _ = _run(tmp_path, "10.0.0.1", bind="10.0.0.9")
    assert out.splitlines() == ["set_real_ip_from 10.0.0.1;"]


def test_the_app_code_is_not_owned_by_the_user_it_runs_as():
    df = (ROOT / "docker" / "Dockerfile").read_text()
    assert not re.search(r"chown\b[^\n]*\s/app(\s|$)", df)
    assert "USER ctem" in df


def test_the_collector_image_python_is_patched():
    """Both images pin an exact, patched Python (a moving tag hides what ships from the SBOM and the scanners)."""
    for df in (ROOT / "api" / "collector" / "agent" / "Dockerfile", ROOT / "docker" / "Dockerfile"):
        m = re.search(r"^FROM python:(\d+)\.(\d+)\.(\d+)-", df.read_text(), re.M)
        assert m, f"{df} must pin an exact Python version"
        assert tuple(int(x) for x in m.groups()) >= (3, 12, 14)


def test_the_scheduler_keeps_its_schedule_file_outside_the_read_only_code():
    compose = (ROOT / "docker" / "docker-compose.yml").read_text()
    beat = [ln for ln in compose.splitlines() if " beat " in ln and "celery" in ln]
    assert beat and all("--schedule /tmp/" in ln for ln in beat)
