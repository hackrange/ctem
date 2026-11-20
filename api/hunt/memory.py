"""Token savers: saved search plans (kept) and finished write-ups (24h)."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.settings import AppSetting

log = logging.getLogger("open-ctem.hunt")
PLAN_PREFIX = "hunt_plan_"
ANSWER_TTL = 86400


def normalize(question: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9.\-_\\ ]", " ", question.lower())).strip()


def plan_key(question: str) -> str:
    return PLAN_PREFIX + hashlib.sha256(normalize(question).encode()).hexdigest()[:24]


def schema_print(schema: dict | None) -> str:
    idx = (schema or {}).get("indexes", {})
    return hashlib.sha256("|".join(f"{k}:{v.get('fingerprint')}" for k, v in sorted(idx.items())).encode()).hexdigest()[:16]


async def load_plan(db: AsyncSession, question: str, fp: str) -> list[dict] | None:
    row = (await db.execute(select(AppSetting).where(AppSetting.key == plan_key(question)))).scalar_one_or_none()
    if not row or not row.value:
        return None
    try:
        saved = json.loads(row.value)
    except ValueError:
        return None
    if saved.get("schema") != fp:
        return None  # Splunk changed shape since; plan afresh
    saved["uses"] = int(saved.get("uses", 0)) + 1
    saved["last_used"] = datetime.now(timezone.utc).isoformat()
    row.value = json.dumps(saved)
    await db.commit()
    return saved.get("lookups") or None


async def save_plan(db: AsyncSession, question: str, fp: str, lookups: list[dict]) -> None:
    keep = [{k: lk[k] for k in ("source", "title", "why", "spl", "table", "filters", "limit") if k in lk}
            for lk in lookups]
    if not keep:
        return
    key = plan_key(question)
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    row = row or AppSetting(key=key, is_sensitive=False)
    row.value = json.dumps({"question": question[:500], "schema": fp, "lookups": keep, "uses": 0,
                            "created": datetime.now(timezone.utc).isoformat()})
    db.add(row)
    await db.commit()


async def learned_searches(db: AsyncSession, limit: int = 50) -> list[dict]:
    rows = (await db.execute(select(AppSetting).where(AppSetting.key.like(PLAN_PREFIX + "%"))
                             .order_by(AppSetting.updated_at.desc()).limit(limit))).scalars()
    out = []
    for row in rows:
        try:
            saved = json.loads(row.value or "{}")
        except ValueError:
            continue
        for lk in saved.get("lookups", []):
            if lk.get("source") == "splunk" and lk.get("spl"):
                out.append({"category": "learned", "title": lk.get("title", "Search"),
                            "description": f"{lk.get('why', '')} (from: \"{saved.get('question', '')}\")".strip(),
                            "spl": lk["spl"], "question": saved.get("question")})
    return out


def _redis():
    import redis
    from api.core.config import get_settings
    return redis.from_url(get_settings().redis_url)


def answer_key(question: str, time_range: str, evidence: str) -> str:
    return "hunt_answer:" + hashlib.sha256(f"{normalize(question)}|{time_range}|{evidence}".encode()).hexdigest()


def cached_answer(key: str) -> dict | None:
    try:
        raw = _redis().get(key)
        return json.loads(raw) if raw else None
    except Exception:
        log.warning("hunt answer cache unavailable")
        return None


def store_answer(key: str, answer: dict) -> None:
    try:
        _redis().set(key, json.dumps(answer), ex=ANSWER_TTL)
    except Exception:
        log.warning("hunt answer cache unavailable")
