"""Cache-busted static URLs: /static/js/x.js?v=<content hash>, so a deploy is never hidden by browser cache."""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

_ROOT = (Path(__file__).parent / "static").resolve()


@lru_cache(maxsize=256)
def static_url(path: str) -> str:
    """Hash is computed once per process; a new deploy is a new process."""
    rel = path.lstrip("/")
    target = (_ROOT / rel).resolve()
    if _ROOT not in target.parents or not target.is_file():
        return f"/static/{rel}"
    digest = hashlib.sha256(target.read_bytes()).hexdigest()[:10]
    return f"/static/{rel}?v={digest}"


def install(templates) -> None:
    templates.env.globals["static"] = static_url
