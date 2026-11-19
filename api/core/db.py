"""Database engine, session factory, and boot-time migration."""
from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.core.config import get_settings

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
    """Create tables and add any missing columns (no Alembic needed for v1)."""
    global _engine, _session_factory

    _engine = _make_engine()
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    from api.models.base import Base  # noqa: PLC0415 -- avoids circular at module level
    import api.models.user          # noqa: F401 -- registers models with metadata
    import api.models.device        # noqa: F401
    import api.models.vuln          # noqa: F401
    import api.models.risk          # noqa: F401
    import api.models.integration   # noqa: F401
    import api.models.tag           # noqa: F401
    import api.models.settings      # noqa: F401
    import api.models.identity      # noqa: F401 -- ITDR, posture, SaaS/AI app records

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns, Base.metadata)

    await _seed_builtin_roles()


def _add_missing_columns(conn, metadata) -> None:  # noqa: ANN001
    """Add columns that exist in models but not yet in DB (safe forward-only migration)."""
    inspector = inspect(conn)
    for table in metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {col["name"] for col in inspector.get_columns(table.name)}
        for col in table.columns:
            if col.name not in existing:
                col_type = col.type.compile(conn.dialect)
                nullable = "NULL" if col.nullable else "NOT NULL"
                default = ""
                if col.default is not None and hasattr(col.default, "arg"):
                    default = f" DEFAULT {col.default.arg!r}"
                conn.execute(
                    text(f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col_type} {nullable}{default}")
                )


async def _seed_builtin_roles() -> None:
    """Create the five built-in roles if they don't exist yet."""
    from api.models.user import Role

    builtin = [
        ("admin",               "Administrator",        "Full access including configuration"),
        ("cyber",               "Cyber",                "All assets and findings, read-write on remediation"),
        ("it_user",             "IT User",              "Own assets and assigned devices only"),
        ("business_stakeholder","Business Stakeholder", "Risk summary for assigned business unit"),
        ("read_only",           "Read Only",            "Configurable read-only scope"),
    ]

    async with get_session() as db:
        for name, display, desc in builtin:
            existing = await db.get(Role, name)
            if existing is None:
                db.add(Role(name=name, display_name=display, description=desc, is_builtin=True))
        await db.commit()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    if _session_factory is None:
        raise RuntimeError("Database not initialized -- call init_db() first")
    async with _session_factory() as session:
        yield session


async def close_db() -> None:
    if _engine:
        await _engine.dispose()
