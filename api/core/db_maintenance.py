"""Keeping PostgreSQL quick as the data grows (Admin > Maintenance > Database). Postgres only; nothing here locks a
table for more than a moment:

  tune      big, busy tables get autovacuum thresholds sized for them: the default waits until a fifth of a table is dead
            rows, which on a table of millions means a million dead rows slowing every scan first
  nightly   VACUUM (ANALYZE) every table with many dead rows, and ANALYZE every table that changed a lot since its last
            analyze, so the planner's numbers are fresh
  weekly    rebuild an index only when it is measurably bloated (pgstattuple's leaf density under 60%), one at a time with
            REINDEX CONCURRENTLY, so reads and writes carry on

What each run did is kept and shown on the page."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select, text

log = logging.getLogger("open-ctem.db_maintenance")
RESULT_KEY = "db_maintenance_last"
# (table, autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor): the share of rows that may change first
TUNED = (("findings", 0.02, 0.01), ("software_installs", 0.05, 0.02), ("intel_indicators", 0.05, 0.02), ("edr_events", 0.05, 0.02),
         ("vulnerabilities", 0.05, 0.02), ("devices", 0.05, 0.02), ("users", 0.05, 0.02), ("risk_scores", 0.05, 0.02),
         ("device_tags", 0.05, 0.02), ("feed_alerts", 0.05, 0.02), ("risk_score_history", 0.05, 0.02))
DEAD_MIN, DEAD_SHARE = 10_000, 0.05          # VACUUM when this many dead rows and this share of live ones
CHANGED_SHARE = 0.10                          # ANALYZE when this share changed since the last analyze
LEAF_DENSITY = 60.0                           # reindex an index whose pages are less full than this (%)
MIN_INDEX_MB, MAX_INDEX_MB, MAX_REINDEX = 10, 5_000, 10


_IDENT = __import__("re").compile(r'^[A-Za-z_][A-Za-z0-9_$]{0,62}$|^"[^"]{1,63}"$')


def _q(name: str) -> str:
    """A table or index name from pg_catalog, as a quoted identifier. These statements can't take bound parameters,
    so a name that isn't a plain identifier is refused rather than quoted."""
    name = name.removeprefix("public.")
    if not _IDENT.match(name):
        raise ValueError("not a plain identifier")
    return name if name.startswith('"') else '"' + name + '"'


def _ddl(sql: str):
    return text(sql)  # nosec B608 - identifiers only via _q (pg_catalog names, checked); numbers are module constants


def _newest(*ds):
    ds = [d for d in ds if d]
    return max(ds).isoformat() if ds else None


async def _engine():
    """The app's engine on PostgreSQL; None anywhere else (SQLite in development and tests is left alone)."""
    from api.core import db as dbmod
    from api.core.config import get_settings
    if not str(get_settings().database_url).startswith("postgresql"):
        return None
    if dbmod._engine is None:
        await dbmod.init_db()
    return dbmod._engine


async def table_stats(conn, limit: int = 15) -> list[dict]:
    rows = (await conn.execute(text(
        "SELECT relname, n_live_tup, n_dead_tup, pg_total_relation_size(relid) AS bytes, last_vacuum, last_autovacuum, "
        "last_analyze, last_autoanalyze FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT :n"),
        {"n": limit})).mappings().all()
    return [{"table": r["relname"], "rows": r["n_live_tup"], "dead": r["n_dead_tup"], "mb": round(r["bytes"] / 1048576, 1),
             "dead_pct": round(100 * r["n_dead_tup"] / max(r["n_live_tup"], 1), 1),
             "vacuumed": _newest(r["last_vacuum"], r["last_autovacuum"]), "analyzed": _newest(r["last_analyze"], r["last_autoanalyze"])}
            for r in rows]


async def run(reindex: bool = False) -> dict:
    """The nightly pass (and, with reindex, the weekly one). Returns what it did; kept for the page."""
    eng = await _engine()
    if eng is None or eng.dialect.name != "postgresql":
        return {"skipped": "not PostgreSQL"}
    started, out = time.time(), {"at": datetime.now(timezone.utc).isoformat(), "tuned": [], "vacuumed": [], "analyzed": [],
                                 "reindexed": [], "errors": []}
    async with eng.connect() as raw:
        conn = await raw.execution_options(isolation_level="AUTOCOMMIT")   # VACUUM and REINDEX CONCURRENTLY can't run in a transaction
        await conn.execute(text("SET lock_timeout = '5s'"))
        await conn.execute(text("SET statement_timeout = 0"))
        have = set((await conn.execute(text("SELECT relname FROM pg_stat_user_tables"))).scalars())
        for table, vac, ana in TUNED:
            if table not in have:
                continue
            try:
                await conn.execute(_ddl(f"ALTER TABLE {_q(table)} SET (autovacuum_vacuum_scale_factor = {float(vac)}, "
                                        f"autovacuum_analyze_scale_factor = {float(ana)})"))
                out["tuned"].append(table)
            except Exception as e:  # noqa: BLE001 -- a busy table is tuned next time
                out["errors"].append(f"tune {table}: {type(e).__name__}")
        stats = (await conn.execute(text("SELECT relname, n_live_tup, n_dead_tup, n_mod_since_analyze FROM pg_stat_user_tables"))).all()
        for name, live, dead, mod in stats:
            try:
                if dead >= DEAD_MIN and dead >= DEAD_SHARE * max(live, 1):
                    await conn.execute(_ddl(f"VACUUM (ANALYZE) {_q(name)}"))
                    out["vacuumed"].append({"table": name, "dead": dead})
                elif mod and mod >= CHANGED_SHARE * max(live, 1) and mod >= 1000:
                    await conn.execute(_ddl(f"ANALYZE {_q(name)}"))
                    out["analyzed"].append(name)
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"{name}: {type(e).__name__}")
        if reindex:
            await _reindex(conn, out)
    out["took_s"] = round(time.time() - started, 1)
    await _save(out)
    log.info("database maintenance: %d tuned, %d vacuumed, %d analyzed, %d reindexed, %d errors in %ss", len(out["tuned"]),
             len(out["vacuumed"]), len(out["analyzed"]), len(out["reindexed"]), len(out["errors"]), out["took_s"])
    return out


async def _reindex(conn, out: dict) -> None:
    try:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgstattuple"))
    except Exception as e:  # noqa: BLE001 -- without it nothing is measured, so nothing is rebuilt
        out["errors"].append(f"pgstattuple unavailable: {type(e).__name__}")
        return
    rows = (await conn.execute(text(
        "SELECT i.indexrelid::regclass::text AS idx, pg_relation_size(i.indexrelid) AS bytes FROM pg_index i "
        "JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_am a ON a.oid = c.relam JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE a.amname = 'btree' AND n.nspname = 'public' AND pg_relation_size(i.indexrelid) BETWEEN :lo AND :hi "
        "ORDER BY pg_relation_size(i.indexrelid) DESC"), {"lo": MIN_INDEX_MB * 1048576, "hi": MAX_INDEX_MB * 1048576})).all()
    for idx, size in rows:
        if len(out["reindexed"]) >= MAX_REINDEX:
            break
        try:
            density = (await conn.execute(text("SELECT avg_leaf_density FROM pgstatindex(:i)"), {"i": idx})).scalar()
            if density is not None and density < LEAF_DENSITY:
                await conn.execute(_ddl(f"REINDEX INDEX CONCURRENTLY {_q(idx)}"))
                after = (await conn.execute(text("SELECT pg_relation_size(CAST(:i AS regclass))"), {"i": idx})).scalar()
                out["reindexed"].append({"index": idx, "mb_before": round(size / 1048576, 1), "mb_after": round((after or 0) / 1048576, 1),
                                         "leaf_density": round(float(density), 1)})
        except Exception as e:  # noqa: BLE001 -- one index failing leaves the others
            out["errors"].append(f"reindex {idx}: {type(e).__name__}")


async def _save(out: dict) -> None:
    from api.core.db import get_session
    from api.models.settings import AppSetting
    async for db in get_session():
        row = (await db.execute(select(AppSetting).where(AppSetting.key == RESULT_KEY))).scalar_one_or_none()
        row = row or AppSetting(key=RESULT_KEY, is_sensitive=False)
        row.value = json.dumps(out)
        db.add(row)
        await db.commit()
        break


async def status() -> dict:
    """For the page: the biggest tables with their dead rows and last vacuum and analyze, and the last run."""
    from api.core.db import get_session
    from api.models.settings import AppSetting
    eng = await _engine()
    if eng is None or eng.dialect.name != "postgresql":
        return {"available": False}
    async with eng.connect() as conn:
        tables = await table_stats(conn)
        size = (await conn.execute(text("SELECT pg_database_size(current_database())"))).scalar()
    last = None
    async for db in get_session():
        row = (await db.execute(select(AppSetting).where(AppSetting.key == RESULT_KEY))).scalar_one_or_none()
        last = json.loads(row.value) if row and row.value else None
        break
    return {"available": True, "database_mb": round((size or 0) / 1048576, 1), "tables": tables, "last_run": last}
