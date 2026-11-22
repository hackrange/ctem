"""Exceptions made in CTEM, mirrored to GitHub Code Review so both tools agree.

When an exception is approved in CTEM, each GitHub Code Review finding it covers gets the same in GCR:
  code finding  an exception request (reason, end date, a CTEM reference), then GCR's approve, which needs the
                approve scope (an administrator's token). Without it the request waits for an admin in GCR.
  site (DAST)   an exception decision on the scan's finding, until the same end date (needs the external scope).
Each finding remembers what was sent (details["tool_exception"]), so nothing is sent twice. Only the configured
GCR host is called, through the SSRF-safe client; failures are recorded, never raised into CTEM's own flow."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

log = logging.getLogger("open-ctem.gcr-writeback")
SRC = "github_code_review"


def _fp(exc) -> bool:
    return getattr(exc, "kind", None) == "false_positive"


def _reason(exc) -> str:
    """GCR wants at least 20 characters and keeps up to 2,000."""
    what = "False positive, per CTEM" if _fp(exc) else "Accepted in CTEM"
    text = f"{what} ({exc.decided_by or exc.requested_by}): " + " ".join(str(exc.reason or "").split())
    return text[:1900].ljust(20, ".")


def _ends(exc) -> str:
    end = exc.expires_at if exc.expires_at.tzinfo else exc.expires_at.replace(tzinfo=timezone.utc)
    cap = datetime.now(timezone.utc) + timedelta(days=364)   # GCR allows up to a year
    return min(end, cap).date().isoformat()


async def _find_in_scan(g, f) -> tuple:
    """The site, scan and finding key for a site finding stored before they were kept: from the site's latest
    scan in GCR, matched by title."""
    dev = getattr(f, "device", None)
    sid = str(getattr(dev, "source_id", "") or "")
    if not sid.startswith("site:") or not sid[5:].isdigit():
        return None, None, None
    scan = await g.latest_scan(int(sid[5:]))
    title = (getattr(getattr(f, "vuln", None), "title", "") or "").strip().lower()
    for x in (scan or {}).get("findings") or []:
        if (x.get("title") or "").strip().lower() == title and x.get("key"):
            return int(sid[5:]), scan.get("id"), str(x["key"])[:64]
    return None, None, None


async def _one(g, f, exc) -> dict:
    d = f.details or {}
    if f.domain == "web":
        site, scan, key = d.get("site_id"), d.get("scan_id"), d.get("key")
        if not (str(site).isdigit() and str(scan).isdigit() and key and str(key).isalnum()):
            site, scan, key = await _find_in_scan(g, f)   # older rows: look it up in the site's latest scan
        if not (str(site).isdigit() and str(scan).isdigit() and key and str(key).isalnum()):
            return {"state": "skipped", "why": "GCR's latest scan of the site no longer lists it"}
        body = {"kind": "false_positive", "reason": _reason(exc), "persist": True} if _fp(exc) else \
            {"kind": "exception", "reason": _reason(exc), "expires": _ends(exc), "persist": True}
        code, _ = await g.post(f"/external/assets/{int(site)}/scans/{int(scan)}/findings/{key}/decision", body)
        return {"state": "approved" if code in (200, 201) else "failed", "code": code}
    if not str(f.source_id or "").isdigit():
        return {"state": "skipped", "why": "no GCR finding number"}
    code, body = await g.post(f"/findings/{int(f.source_id)}/exceptions",
                              {"reason": _reason(exc), "expires": _ends(exc), "ticket": f"CTEM {str(exc.id)[:8]}"})
    if code == 409:
        return {"state": "already", "code": code}   # GCR already has a pending or approved exception on it
    if code not in (200, 201) or not str(body.get("id", "")).isdigit():
        return {"state": "failed", "code": code}
    eid = int(body["id"])
    code2, _ = await g.post(f"/exceptions/{eid}/approve", {"note": f"Approved in CTEM ({str(exc.id)[:8]})"})
    return {"state": "approved" if code2 in (200, 201) else "requested", "gcr_exception": eid,
            "why": None if code2 in (200, 201) else "the token can't approve (needs the approve scope); an admin approves it in GCR"}


async def push(db, exception_ids: list[str] | None = None) -> int:
    """Send CTEM's approved exceptions on GCR findings to GCR. All that haven't been sent, or just these."""
    from api.core.vuln_exceptions import is_active
    from api.integrations.gcr_client import Gcr
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AuditLog
    from api.models.vuln import Finding, VulnException
    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.github_code_review,
                                                            IntegrationConfig.is_enabled.is_(True)))).scalars().first()
    if cfg is None or (cfg.config or {}).get("no_push_exceptions") in (True, "true", "1"):
        return 0
    from sqlalchemy.orm import selectinload
    q = (select(Finding).options(selectinload(Finding.device), selectinload(Finding.vuln))
         .where(Finding.source == SRC, Finding.exception_id.is_not(None)))
    if exception_ids:
        q = q.where(Finding.exception_id.in_([str(i) for i in exception_ids][:200]))
    findings = [f for f in (await db.execute(q.limit(5000))).scalars()
                if ((f.details or {}).get("tool_exception") or {}).get("ctem") != str(f.exception_id)
                or ((f.details or {}).get("tool_exception") or {}).get("state") in ("failed", "skipped")]
    if not findings:
        return 0
    excs = {str(e.id): e for e in (await db.execute(select(VulnException).where(
        VulnException.id.in_({str(f.exception_id) for f in findings})))).scalars()}
    sent = 0
    async with Gcr({k: v for k, v in (cfg.config or {}).items() if v not in ("", None)}) as g:
        for f in findings:
            exc = excs.get(str(f.exception_id))
            if exc is None or not is_active(exc):
                continue
            try:
                res = await _one(g, f, exc)
            except Exception as e:  # noqa: BLE001 -- recorded on the finding, retried next time
                log.warning("GCR exception write-back failed: %s", type(e).__name__)
                res = {"state": "failed", "why": type(e).__name__}
            f.details = {**(f.details or {}), "tool_exception": {"ctem": str(exc.id), "at": datetime.now(timezone.utc).isoformat(),
                                                                 **{k: v for k, v in res.items() if v is not None}}}
            sent += res["state"] in ("approved", "requested", "already")
            db.add(AuditLog(actor_username="system", action="exception.pushed_to_gcr", resource_type="vuln_exception",
                            resource_id=str(exc.id), detail=f"finding {f.source_id}: {res['state']}"))
    await db.commit()
    log.info("GCR exception write-back: %d sent of %d", sent, len(findings))
    return sent
