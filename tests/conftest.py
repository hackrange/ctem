"""Shared test fixtures."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.models.base import Base

# In-memory SQLite for tests -- fast, no Postgres needed
_TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="session")
async def engine():
    eng = create_async_engine(_TEST_DB_URL, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine) -> AsyncGenerator[AsyncSession, None]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db) -> AsyncGenerator[AsyncClient, None]:
    """Test client with DB session override."""
    from api.core.db import get_session
    from api.main import create_app

    app = create_app()
    app.dependency_overrides[get_session] = lambda: db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def admin_user(db: AsyncSession):
    from api.models.user import User, UserRole
    user = User(
        id=uuid.uuid4(),
        username=f"admin_{uuid.uuid4().hex[:6]}",
        is_active=True,
        is_local=True,
        is_locked=False,
    )
    db.add(user)
    db.add(UserRole(user_id=user.id, role_name="admin"))
    await db.commit()
    return user


@pytest_asyncio.fixture
async def cyber_user(db: AsyncSession):
    from api.models.user import User, UserRole
    user = User(
        id=uuid.uuid4(),
        username=f"cyber_{uuid.uuid4().hex[:6]}",
        is_active=True,
        is_local=True,
        is_locked=False,
    )
    db.add(user)
    db.add(UserRole(user_id=user.id, role_name="cyber"))
    await db.commit()
    return user


@pytest_asyncio.fixture
async def db_session(db: AsyncSession):
    """Alias so tests can be explicit about what they're writing to."""
    return db


def _authed_client(app, db, user):
    """Return an AsyncClient with the given user injected as current_user."""
    from api.auth.middleware import get_current_user
    from api.core.db import get_session

    app.dependency_overrides[get_session] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest_asyncio.fixture
async def client_cyber(db: AsyncSession, cyber_user) -> AsyncGenerator[AsyncClient, None]:
    from api.main import create_app
    app = create_app()
    async with _authed_client(app, db, cyber_user) as ac:
        yield ac


@pytest_asyncio.fixture
async def client_no_auth(db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    from api.core.db import get_session
    from api.main import create_app
    app = create_app()
    app.dependency_overrides[get_session] = lambda: db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def read_only_user(db: AsyncSession):
    from api.models.user import User, UserRole
    user = User(id=uuid.uuid4(), username=f"ro_{uuid.uuid4().hex[:6]}",
                is_active=True, is_local=True, is_locked=False)
    db.add(user)
    db.add(UserRole(user_id=user.id, role_name="read_only"))
    await db.commit()
    return user


@pytest_asyncio.fixture
async def client_read_only(db: AsyncSession, read_only_user) -> AsyncGenerator[AsyncClient, None]:
    from api.main import create_app
    app = create_app()
    async with _authed_client(app, db, read_only_user) as ac:
        yield ac


@pytest_asyncio.fixture
async def it_user(db: AsyncSession):
    from api.models.user import User, UserRole
    user = User(id=uuid.uuid4(), username=f"it_{uuid.uuid4().hex[:6]}",
                is_active=True, is_local=True, is_locked=False)
    db.add(user)
    db.add(UserRole(user_id=user.id, role_name="it_user"))
    await db.commit()
    return user


@pytest_asyncio.fixture
async def client_it_user(db: AsyncSession, it_user) -> AsyncGenerator[AsyncClient, None]:
    from api.main import create_app
    app = create_app()
    async with _authed_client(app, db, it_user) as ac:
        yield ac


@pytest_asyncio.fixture
async def api_token_for(db: AsyncSession):
    """Factory: returns (plain_token, ApiToken) for a given user and allowed IP."""
    from api.models.user import ApiToken

    async def _make(user, allowed_ip="127.0.0.1"):
        plain = secrets.token_hex(32)
        token_hash = hashlib.sha256(plain.encode()).hexdigest()
        t = ApiToken(
            user_id=user.id,
            name="test-token",
            token_hash=token_hash,
            allowed_ips=[allowed_ip],
            is_active=True,
        )
        db.add(t)
        await db.commit()
        return plain, t

    return _make
