"""Database engine, session factory, and boot-time auto-migration."""
from __future__ import annotations

import logging
import re
from collections.abc import AsyncGenerator

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.core.config import get_settings

log = logging.getLogger("open-ctem.db")

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _make_engine():
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=40,
        echo=settings.debug,
    )


async def init_db() -> None:
    """
    Boot-time schema management:
      1. create_all  -- creates any tables that don't exist yet
      2. _evolve     -- adds missing columns and indexes to existing tables
    No manual SQL ever needed after a code upgrade.
    """
    global _engine, _session_factory

    _engine = _make_engine()
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    # Import every model module so their tables register with Base.metadata
    from api.models.base import Base  # noqa: PLC0415
    import api.models.user          # noqa: F401
    import api.models.device        # noqa: F401
    import api.models.vuln          # noqa: F401
    import api.models.risk          # noqa: F401 -- includes ThirdPartyRisk/Gap + RiskException
    import api.models.integration   # noqa: F401
    import api.models.tag           # noqa: F401
    import api.models.settings      # noqa: F401
    import api.models.identity      # noqa: F401
    import api.models.collector     # noqa: F401
    import api.models.grc           # noqa: F401
    import api.models.rules         # noqa: F401
    import api.models.dashboard     # noqa: F401
    import api.models.tag_role      # noqa: F401
    import api.models.user_access   # noqa: F401
    import api.models.software      # noqa: F401
    import api.models.edr_policy    # noqa: F401
    import api.models.alert_feed    # noqa: F401
    import api.models.alert_action  # noqa: F401
    import api.models.alert_allow   # noqa: F401
    import api.models.posture_exception   # noqa: F401
    import api.models.zscaler       # noqa: F401
    import api.models.hunt_data     # noqa: F401
    import api.models.cloud         # noqa: F401
    import api.models.utilization   # noqa: F401
    import api.models.snapshot      # noqa: F401
    import api.models.threat_rule   # noqa: F401

    # Enum values must be added outside any transaction (Postgres requirement)
    async with _engine.connect() as conn:
        ac = await conn.execution_options(isolation_level="AUTOCOMMIT")
        await ac.run_sync(_evolve_enums, Base.metadata)

    async with _engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            # app, worker, and beat boot together; let one migrate while the others wait
            await conn.execute(text("SELECT pg_advisory_xact_lock(7243105)"))
        await conn.run_sync(Base.metadata.create_all)   # new tables only
        await conn.run_sync(_evolve, Base.metadata)      # columns + indexes for existing

    await _run_seed()


# ── Schema evolution (forward-only, non-destructive) ─────────────────────────

_ENUM_WORD = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _evolve_enums(conn, metadata) -> None:
    """Add any new enum values to existing Postgres ENUM types (autocommit required).

    ALTER TYPE takes no bind parameters, so the type and value are written into the statement. Both come
    from the models in this codebase, never from a request, and must still match a plain lowercase word."""
    if conn.dialect.name != "postgresql":
        return
    existing = {(t, v) for t, v in conn.execute(text(
        "SELECT t.typname, e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid"))}
    known_types = {t for t, _ in existing}
    for table in metadata.sorted_tables:
        for col in table.columns:
            type_name = getattr(col.type, "name", None)
            if not hasattr(col.type, "enums") or type_name not in known_types:
                continue   # create_all makes brand-new types with every value
            for val in col.type.enums:
                if (type_name, val) in existing:
                    continue
                if not (_ENUM_WORD.match(type_name) and _ENUM_WORD.match(val)):
                    log.error("enum evolve refused %r.%r: not a plain identifier", type_name, val)
                    continue
                try:
                    conn.execute(text(f"ALTER TYPE {type_name} ADD VALUE IF NOT EXISTS '{val}'"))  # nosec B608 -- allow-listed above
                    existing.add((type_name, val))
                    log.info("enum %s: added value %s", type_name, val)
                except Exception:
                    log.exception("enum evolve failed for %s.%s", type_name, val)


# NOT NULL columns the models made optional. Reviewed one by one; dropping NOT NULL never loses data.
_RELAXED = {"vuln_exceptions": ("vuln_id",)}   # rule exceptions cover many vulnerabilities


def _evolve(conn, metadata) -> None:  # noqa: ANN001
    """
    Safe forward-only DDL:
      - ADD COLUMN for each model column missing from the live DB
      - CREATE INDEX IF NOT EXISTS for each model index missing from the live DB

    Each statement runs in its own savepoint so one failure can't block the rest.
    Type changes and dropped columns are intentionally not automated -- they need
    a carefully reviewed one-time migration, not a boot-time surprise.
    """
    inspector = inspect(conn)

    for table in metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue  # just created by create_all; nothing to evolve

        existing_cols = {col["name"] for col in inspector.get_columns(table.name)}
        existing_idx  = {idx["name"] for idx in inspector.get_indexes(table.name)}

        # ── New columns ───────────────────────────────────────────────────────
        for col in table.columns:
            if col.name in existing_cols:
                continue
            col_type = col.type.compile(conn.dialect)
            nullable = "NULL" if col.nullable else "NOT NULL"
            default  = ""
            if col.server_default is not None:
                default = f" DEFAULT {col.server_default.arg}"
            elif col.default is not None and hasattr(col.default, "arg") and not callable(col.default.arg):
                # a Python-side default such as `list` or a lambda has no SQL form; the app fills it on insert
                raw = col.default.arg
                default = f" DEFAULT {raw!r}" if isinstance(raw, str) else f" DEFAULT {raw}"
            # Boolean/integer NOT NULL without a default would reject existing rows.
            # Fall back to NULL so the ALTER always succeeds; app code uses Python defaults.
            if not col.nullable and not default:
                nullable = "NULL"
                log.warning(
                    "auto-migrate: %s.%s added as NULL (no server_default) -- "
                    "set a value manually if NOT NULL is required",
                    table.name, col.name,
                )
            ddl = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col_type} {nullable}{default}"
            try:
                with conn.begin_nested():  # savepoint: a failure must not abort the boot transaction
                    conn.execute(text(ddl))
                log.info("auto-migrate: added column %s.%s", table.name, col.name)
            except Exception as exc:
                log.warning("auto-migrate: skipped column %s.%s -- %s", table.name, col.name, exc)

        # ── Columns that became optional (an explicit, reviewed list) ─────────
        for col_name in _RELAXED.get(table.name, ()):
            col = table.columns.get(col_name)
            live = next((c for c in inspector.get_columns(table.name) if c["name"] == col_name), None)
            if col is None or not col.nullable or live is None or live.get("nullable", True) or conn.dialect.name != "postgresql":
                continue
            try:
                with conn.begin_nested():
                    conn.execute(text(f"ALTER TABLE {table.name} ALTER COLUMN {col_name} DROP NOT NULL"))  # nosec B608 -- names from _RELAXED
                log.info("auto-migrate: %s.%s may now be NULL", table.name, col_name)
            except Exception as exc:
                log.warning("auto-migrate: couldn't relax %s.%s -- %s", table.name, col_name, exc)

        # ── New indexes ───────────────────────────────────────────────────────
        for idx in table.indexes:
            if not idx.name or idx.name in existing_idx:
                continue
            try:
                # Render (not run) the CREATE INDEX so it can go inside a savepoint
                from sqlalchemy.schema import CreateIndex
                create_stmt = str(CreateIndex(idx).compile(dialect=conn.dialect)).strip()
                # PostgreSQL supports IF NOT EXISTS; wrap for safety
                if "IF NOT EXISTS" not in create_stmt.upper():
                    create_stmt = create_stmt.replace("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1)
                with conn.begin_nested():
                    conn.execute(text(create_stmt))
                log.info("auto-migrate: created index %s on %s", idx.name, table.name)
            except Exception as exc:
                log.warning("auto-migrate: skipped index %s -- %s", idx.name, exc)


# ── Seed on startup ───────────────────────────────────────────────────────────

async def _run_seed() -> None:
    from api.core.seed import run_seed
    settings = get_settings()
    async with _session_factory() as db:
        await run_seed(db, settings)


# ── Session helpers ───────────────────────────────────────────────────────────

def init_db_worker() -> None:
    """Set up engine/session for Celery workers -- NullPool so each asyncio.run() gets fresh connections."""
    global _engine, _session_factory
    if _session_factory is not None:
        return
    from sqlalchemy.pool import NullPool
    settings = get_settings()
    _engine = create_async_engine(
        settings.database_url,
        poolclass=NullPool,
        echo=settings.debug,
    )
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    # All models must be imported so SQLAlchemy can resolve relationships
    import api.models.user          # noqa: F401
    import api.models.device        # noqa: F401
    import api.models.vuln          # noqa: F401
    import api.models.risk          # noqa: F401
    import api.models.integration   # noqa: F401
    import api.models.tag           # noqa: F401
    import api.models.settings      # noqa: F401
    import api.models.identity      # noqa: F401
    import api.models.rules         # noqa: F401
    import api.models.dashboard     # noqa: F401
    import api.models.tag_role      # noqa: F401
    import api.models.user_access   # noqa: F401
    import api.models.software      # noqa: F401
    import api.models.edr_policy    # noqa: F401
    import api.models.alert_feed    # noqa: F401
    import api.models.alert_action  # noqa: F401
    import api.models.alert_allow   # noqa: F401
    import api.models.zscaler       # noqa: F401
    import api.models.hunt_data     # noqa: F401
    import api.models.cloud         # noqa: F401
    import api.models.utilization   # noqa: F401
    import api.models.snapshot      # noqa: F401
    import api.models.threat_rule   # noqa: F401


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    if _session_factory is None:
        raise RuntimeError("Database not initialized -- call init_db() first")
    async with _session_factory() as session:
        yield session


async def close_db() -> None:
    if _engine:
        await _engine.dispose()
