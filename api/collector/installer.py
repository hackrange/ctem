"""Builds the single-file collector installer: bash template + the agent's Python files inlined."""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import Request

from api.core.config import get_settings

AGENT_DIR = Path(__file__).parent / "agent"
# Fixed list, so nothing outside the agent folder can ever be pulled into a download
AGENT_FILES = ("ctem_collector.py", "collector_core.py", "collector_setup.py", "collector_crypto.py",
               "collector_common.py", "collector_ldap.py", "collector_rapid7.py", "collector_crowdstrike.py",
               "collector_splunk.py", "Dockerfile")
_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")
_CODE_RE = re.compile(r"^([0-9a-f]{64})?$")
_NAME_RE = re.compile(r"^([A-Za-z0-9._-]{1,64})?$")


def public_url(request: Request) -> str | None:
    s = get_settings()
    if s.public_url:
        url = s.public_url.rstrip("/")
        return url if _URL_RE.match(url) else None
    host = (request.headers.get("host") or "").strip()
    bare = host.rsplit(":", 1)[0]
    # Only trust the Host header when it's one we already serve
    if _HOST_RE.match(host) and bare in s.allowed_hosts_list and bare not in ("localhost", "127.0.0.1"):  # nosec - loopback is never a public URL
        return f"https://{host}"
    return None


def _embed(name: str) -> str:
    body = (AGENT_DIR / name).read_text()
    tag = "OCTEM_EOF_" + name.replace(".", "_").upper()
    if tag in body:
        raise RuntimeError(f"{name} contains its own heredoc terminator")
    return f"  cat > \"$STAGE/{name}\" <<'{tag}'\n{body.rstrip()}\n{tag}"


def render_installer(url: str = "", code: str = "", name: str = "") -> str:
    # Values land inside single quotes in bash, so they must be boring
    if url and not _URL_RE.match(url):
        raise ValueError("bad url")
    if not _CODE_RE.match(code) or not _NAME_RE.match(name):
        raise ValueError("bad code or name")
    script = (AGENT_DIR / "install.sh").read_text()
    files = "\n".join(_embed(f) for f in AGENT_FILES)
    return (script.replace("@@CTEM_URL@@", url).replace("@@ENROLL_CODE@@", code)
            .replace("@@COLLECTOR_NAME@@", name).replace("@@EMBEDDED_FILES@@", files))
