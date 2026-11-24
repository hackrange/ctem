"""Shared test fixtures."""
from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import tempfile
import uuid
from collections.abc import AsyncGenerator

import asyncio

import pytest
import pytest_asyncio

# --- Env vars must come before ANY app imports ---
_TEST_SECRET = secrets.token_hex(32)
_TEST_ENC_KEY = secrets.token_hex(32)
_TEST_ENC_SRCH = secrets.token_hex(32)
_DB_FILE = tempfile.mktemp(prefix="ctem_test_", suffix=".db")

os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_DB_FILE}")
os.environ.setdefault("SECRET_KEY", _TEST_SECRET)
os.environ.setdefault("ENCRYPTION_KEY", _TEST_ENC_KEY)
os.environ.setdefault("ENCRYPTION_SEARCH_KEY", _TEST_ENC_SRCH)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402

# Import all model modules so Base.metadata is fully populated before create_all
from api.models.base import Base  # noqa: E402
import api.models.user        # noqa: F401, E402
import api.models.device      # noqa: F401, E402
import api.models.vuln        # noqa: F401, E402
import api.models.tag         # noqa: F401, E402
import api.models.integration # noqa: F401, E402
import api.models.settings    # noqa: F401, E402
import api.models.identity    # noqa: F401, E402
import api.models.risk        # noqa: F401, E402
import api.models.collector   # noqa: F401, E402
import api.models.grc         # noqa: F401, E402
import api.models.rules       # noqa: F401, E402
import api.models.dashboard   # noqa: F401, E402
import api.models.tag_role    # noqa: F401, E402
import api.models.user_access # noqa: F401, E402
import api.models.software    # noqa: F401, E402
import api.models.edr_policy  # noqa: F401, E402
import api.models.alert_feed  # noqa: F401, E402
import api.models.hunt_data  # noqa: F401, E402
import api.models.cloud       # noqa: F401, E402
import api.models.utilization # noqa: F401, E402
import api.models.snapshot    # noqa: F401, E402
import api.models.threat_rule  # noqa: F401, E402
import api.models.alert_action  # noqa: F401, E402

_TEST_DB_URL = os.environ["DATABASE_URL"]

# Browsers send Origin on every write; the CSRF guard expects it
_SAME_ORIGIN = {"Origin": "http://test"}


@pytest.fixture(scope="session")
def event_loop():
    """Single event loop for the whole test session so async fixtures share state."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Engine + sessionmaker created lazily inside the session-scoped fixture so they
# live on the same event loop as the test run.
@pytest_asyncio.fixture(scope="session", autouse=True)
async def _test_engine():
    eng = create_async_engine(_TEST_DB_URL, echo=False,
                               connect_args={"check_same_thread": False})
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # require_permission reads role->perm rows; prod gets these from run_seed()
    from api.core.seed import _seed_roles_and_perms
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        await _seed_roles_and_perms(s)
        await s.commit()
    yield eng
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(_DB_FILE)


@pytest_asyncio.fixture
async def db(_test_engine) -> AsyncGenerator[AsyncSession, None]:
    factory = async_sessionmaker(_test_engine, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db) -> AsyncGenerator[AsyncClient, None]:
    from api.core.db import get_session
    from api.main import create_app

    async def _session_override():
        yield db

    app = create_app()
    app.dependency_overrides[get_session] = _session_override

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=_SAME_ORIGIN) as ac:
        yield ac


def _authed_client(app, db, user):
    from api.auth.middleware import get_current_user
    from api.core.db import get_session

    async def _session_override():
        yield db

    app.dependency_overrides[get_session] = _session_override
    app.dependency_overrides[get_current_user] = lambda: user
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=_SAME_ORIGIN)


async def _make_user(db: AsyncSession, role: str) -> "User":
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from api.models.user import User, UserRole
    uid = str(uuid.uuid4())
    user = User(id=uid, username=f"{role}_{uuid.uuid4().hex[:6]}",
                is_active=True, is_local=True, is_locked=False)
    db.add(user)
    db.add(UserRole(user_id=uid, role_name=role))
    await db.commit()
    # Re-query with eager-loaded roles so role_names works without lazy load
    result = await db.execute(select(User).where(User.id == uid).options(selectinload(User.roles)))
    return result.scalar_one()


@pytest_asyncio.fixture
async def admin_user(db: AsyncSession):
    return await _make_user(db, "admin")


@pytest_asyncio.fixture
async def cyber_user(db: AsyncSession):
    return await _make_user(db, "cyber")


@pytest_asyncio.fixture
async def db_session(db: AsyncSession):
    return db


@pytest_asyncio.fixture
async def client_admin(db: AsyncSession, admin_user) -> AsyncGenerator[AsyncClient, None]:
    from api.main import create_app
    app = create_app()
    async with _authed_client(app, db, admin_user) as ac:
        yield ac


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

    async def _session_override():
        yield db

    app = create_app()
    app.dependency_overrides[get_session] = _session_override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=_SAME_ORIGIN) as ac:
        yield ac


@pytest_asyncio.fixture
async def read_only_user(db: AsyncSession):
    return await _make_user(db, "read_only")


@pytest_asyncio.fixture
async def client_read_only(db: AsyncSession, read_only_user) -> AsyncGenerator[AsyncClient, None]:
    from api.main import create_app
    app = create_app()
    async with _authed_client(app, db, read_only_user) as ac:
        yield ac


@pytest_asyncio.fixture
async def it_user(db: AsyncSession):
    return await _make_user(db, "it_user")


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


@pytest.fixture(autouse=True)
def _many_shippers_per_source(monkeypatch):
    """Tests share one database and each makes its own shippers, so the one-shipper-per-source rule
    (api/collector/service.ONE_PER_FLEET) would trip over earlier tests' leftovers; its own test turns it back on."""
    from api.collector import service
    monkeypatch.setattr(service, "ONE_PER_FLEET", {})


@pytest.fixture(autouse=True)
def _no_builtin_pack(request, monkeypatch):
    """The built-in Threat Curated Rules would join every hunt once any test enables CrowdStrike; only their own
    tests (marked builtin_pack) see them."""
    if request.node.get_closest_marker("builtin_pack") is None:
        from api.hunt import curated_pack

        async def _none(db):
            return 0
        monkeypatch.setattr(curated_pack, "sync", _none)
