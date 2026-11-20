"""Evidence plumbing: run and record checks, signed reports, period history, signing key."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import logging
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import REGISTRY, Check, evaluate
from api.models.grc import GrcCheckResult

log = logging.getLogger("open-ctem.grc")

KEY_SETTING = "grc_evidence_signing_key"
RETENTION_DAYS = 400
MAX_HISTORY_DAYS = 400
CACHE_SECONDS = 300


# ── running checks ────────────────────────────────────────────────────────────

def _cache_key(check: Check, thresholds: dict) -> str:
    blob = json.dumps(thresholds, sort_keys=True)
    return f"grc:check:{check.check_type}:{hashlib.sha256(blob.encode()).hexdigest()[:16]}"


async def _redis():
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


async def run_check(db: AsyncSession, check: Check, params: dict) -> dict:
    """Result for FairTPRM; cached briefly so a burst of monitors doesn't hammer the database."""
    key = _cache_key(check, check.parse(params))
    try:
        r = await _redis()
        hit = await r.get(key)
        await r.aclose()
        if hit:
            return json.loads(hit)
    except Exception:
        log.debug("check cache unavailable")
    body, _ = await evaluate(db, check, params)
    await record(db, body)
    try:
        r = await _redis()
        await r.set(key, json.dumps(body), ex=CACHE_SECONDS)
        await r.aclose()
    except Exception:
        log.debug("check cache unavailable")
    return body


async def record(db: AsyncSession, body: dict) -> None:
    db.add(GrcCheckResult(
        check_type=body["check_type"], check_version=body["check_version"], result=body["result"],
        summary=body["summary"], details=body["details"], thresholds=body["thresholds"],
        data_freshness=body["data_freshness"], measured_at=datetime.fromisoformat(body["measured_at"])))
    await db.commit()


async def run_all(db: AsyncSession) -> dict[str, str]:
    """Daily run of every check at default thresholds, so history has no gaps; prunes old rows."""
    results = {}
    for check in REGISTRY.values():
        body, _ = await evaluate(db, check, {})
        await record(db, body)
        results[check.check_type] = body["result"]
    cut = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    await db.execute(delete(GrcCheckResult).where(GrcCheckResult.measured_at < cut))
    await db.commit()
    return results


# ── signing ───────────────────────────────────────────────────────────────────

async def signing_key(db: AsyncSession):
    """Ed25519 key for evidence signatures. Generated once; private half encrypted at rest."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sqlalchemy.exc import IntegrityError

    from api.core.encryption import decrypt, encrypt
    from api.models.settings import AppSetting

    for _ in range(2):
        row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY_SETTING))).scalar_one_or_none()
        if row and row.value:
            raw = base64.b64decode(json.loads(decrypt(row.value))["private"])
            return Ed25519PrivateKey.from_private_bytes(raw)
        key = Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        db.add(AppSetting(key=KEY_SETTING, is_sensitive=True,
                          value=encrypt(json.dumps({"private": base64.b64encode(raw).decode()}))))
        try:
            await db.commit()
            return key
        except IntegrityError:
            await db.rollback()  # another worker made one first; use theirs
    raise RuntimeError("could not load the evidence signing key")


def public_info(key) -> dict:
    from cryptography.hazmat.primitives import serialization
    pub = key.public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"alg": "Ed25519", "kid": hashlib.sha256(raw).hexdigest()[:16],
            "public_key": base64.b64encode(raw).decode(), "public_key_pem": pem}


def signature_headers(key, body: bytes) -> dict:
    info = public_info(key)
    return {"X-CTEM-Evidence-Alg": "Ed25519", "X-CTEM-Evidence-Kid": info["kid"],
            "X-CTEM-Evidence-Signature": base64.b64encode(key.sign(body)).decode(),
            "X-CTEM-Content-SHA256": hashlib.sha256(body).hexdigest()}


# ── reports ───────────────────────────────────────────────────────────────────

def _meta(body: dict, rows: int, truncated: bool, instance: str) -> dict:
    return {"generated_at": body["measured_at"], "instance": instance, "check_type": body["check_type"],
            "check_version": body["check_version"], "name": body["name"], "result": body["result"],
            "summary": body["summary"], "thresholds": body["thresholds"], "data_freshness": body["data_freshness"],
            "rows": rows, "truncated": truncated}


def render(body: dict, outcome, fmt: str, instance: str, max_rows: int) -> tuple[bytes, str]:
    from api.core.csv_export import safe_cell
    rows = outcome.rows[:max_rows]
    meta = _meta(body, len(rows), len(outcome.rows) >= max_rows, instance)
    if fmt == "json":
        doc = {"meta": meta, "columns": outcome.columns, "rows": rows}
        return json.dumps(doc, separators=(",", ":"), default=str).encode(), "application/json"
    buf = io.StringIO()
    for k, v in meta.items():
        # Comment lines carry the context an auditor needs; values are flattened and made formula-safe
        buf.write(f"# {k}: {safe_cell(json.dumps(v) if isinstance(v, (dict, list)) else v)}\n")
    w = csv.writer(buf)
    w.writerow(outcome.columns)
    for r in rows:
        w.writerow([safe_cell(r.get(c)) for c in outcome.columns])
    return buf.getvalue().encode(), "text/csv; charset=utf-8"


# ── history ───────────────────────────────────────────────────────────────────

async def history(db: AsyncSession, check_type: str, start: date, end: date) -> dict:
    if end < start:
        raise ValueError("to must be on or after from")
    if (end - start).days > MAX_HISTORY_DAYS:
        raise ValueError(f"window is limited to {MAX_HISTORY_DAYS} days")
    lo = datetime.combine(start, time.min, tzinfo=timezone.utc)
    hi = datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc)
    rows = (await db.execute(select(GrcCheckResult).where(
        GrcCheckResult.check_type == check_type, GrcCheckResult.measured_at >= lo, GrcCheckResult.measured_at < hi)
        .order_by(GrcCheckResult.measured_at))).scalars().all()
    days: dict[str, GrcCheckResult] = {}
    for r in rows:  # last run of each day stands for that day
        days[r.measured_at.date().isoformat()] = r
    tally = {"pass": 0, "warning": 0, "fail": 0, "error": 0}  # nosec B105 - result names, not a password
    series = []
    for d in sorted(days):
        r = days[d]
        tally[r.result] = tally.get(r.result, 0) + 1
        series.append({"date": d, "result": r.result, "summary": r.summary, "check_version": r.check_version})
    window = (end - start).days + 1
    return {"check_type": check_type, "from": start.isoformat(), "to": end.isoformat(), "days_in_window": window,
            "days_measured": len(series), "days_missing": window - len(series), "tally": tally,
            "failing_dates": [s["date"] for s in series if s["result"] in ("fail", "error")], "days": series}
