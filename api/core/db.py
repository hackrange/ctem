"""Database engine, session factory, and boot-time auto-migration."""
from __future__ import annotations

import logging
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

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)   # new tables only
        await conn.run_sync(_evolve, Base.metadata)      # columns + indexes for existing

    await _seed_builtin_roles()


# ── Schema evolution (forward-only, non-destructive) ─────────────────────────

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
            elif col.default is not None and hasattr(col.default, "arg"):
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
                conn.execute(text(ddl))
                log.info("auto-migrate: added column %s.%s", table.name, col.name)
            except Exception as exc:
                log.warning("auto-migrate: skipped column %s.%s -- %s", table.name, col.name, exc)

        # ── New indexes ───────────────────────────────────────────────────────
        for idx in table.indexes:
            if not idx.name or idx.name in existing_idx:
                continue
            try:
                # Let SQLAlchemy render the full CREATE INDEX statement
                create_stmt = str(
                    idx.create(bind=conn).compile(conn.dialect)  # type: ignore[arg-type]
                ).strip()
                # PostgreSQL supports IF NOT EXISTS; wrap for safety
                if "IF NOT EXISTS" not in create_stmt.upper():
                    create_stmt = create_stmt.replace("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1)
                conn.execute(text(create_stmt))
                log.info("auto-migrate: created index %s on %s", idx.name, table.name)
            except Exception as exc:
                log.warning("auto-migrate: skipped index %s -- %s", idx.name, exc)


# ── Built-in roles seed ───────────────────────────────────────────────────────

async def _seed_builtin_roles() -> None:
    from api.models.user import Role

    builtin = [
        ("admin",                "Administrator",        "Full access including configuration"),
        ("cyber",                "Cyber",                "All assets and findings, read-write on remediation"),
        ("it_user",              "IT User",              "Own assets and assigned devices only"),
        ("business_stakeholder", "Business Stakeholder", "Risk summary for assigned business unit"),
        ("read_only",            "Read Only",            "Configurable read-only scope"),
    ]

    async with get_session() as db:
        for name, display, desc in builtin:
            existing = await db.get(Role, name)
            if existing is None:
                db.add(Role(name=name, display_name=display, description=desc, is_builtin=True))
        await db.commit()


# ── Session helpers ───────────────────────────────────────────────────────────

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    if _session_factory is None:
        raise RuntimeError("Database not initialized -- call init_db() first")
    async with _session_factory() as session:
        yield session


async def close_db() -> None:
    if _engine:
        await _engine.dispose()
