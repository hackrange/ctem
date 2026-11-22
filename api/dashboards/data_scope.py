"""A dashboard's Data shown: each viewer's own access (the default), or everything for everyone it's shared with.

Admins and cyber set "everything" directly, for a time or with no end. Anyone else asking for it files a request an
admin or cyber approves (with a time limit) or denies, and anyone else changing or publishing a dashboard that shows
everything puts it back to each viewer's own access, with a new request, so every wider view is one someone approved.
Only the published widgets are ever evaluated this way (api/routes/dashboards.py, _published_wide)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from api.models.dashboard import Dashboard
from api.models.user import User


def can_widen(u: User) -> bool:
    """Who may let a dashboard show everyone all the data: the roles that see every finding themselves."""
    return bool({"admin", "cyber"} & set(u.role_names))


def _ask(d: Dashboard, u: User, why: str) -> None:
    """Back to each viewer's own access, with a request for an admin or cyber to approve the wider view."""
    d.data_scope, d.scope_until = "viewer", None
    d.scope_request = {"by": u.username, "at": datetime.now(timezone.utc).isoformat(), "why": why}


def _until(days: int | None):
    return datetime.now(timezone.utc) + timedelta(days=days) if days else None


def shows_everything(d: Dashboard) -> bool:
    """Set to everything, and not past the end an approver gave it."""
    if d.data_scope != "everything":
        return False
    end = d.scope_until
    if end is not None and end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)   # sqlite hands back naive timestamps
    return end is None or end > datetime.now(timezone.utc)


def _scope_change(d: Dashboard, u: User, wanted: str | None, days: int | None = None) -> bool:
    """Apply a save's Data shown choice. Admins and cyber set it directly; anyone else asking for everything files a
    request, and anyone else saving a dashboard that shows everything puts it back up for approval. True if pending."""
    if can_widen(u):
        if wanted is not None:
            d.data_scope, d.scope_request = wanted, None
            d.scope_until = _until(days) if wanted == "everything" else None
        return False
    if wanted == "viewer":
        d.data_scope, d.scope_request = "viewer", None
    elif wanted == "everything" or shows_everything(d):
        if not d.scope_request:
            _ask(d, u, "asked for it" if wanted == "everything" and d.data_scope != "everything" else "changed after it was approved")
    return bool(d.scope_request)
