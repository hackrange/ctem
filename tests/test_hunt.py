"""Hunt API: access, ownership, and input checks."""
from __future__ import annotations

import pytest


class _Task:
    id = "task-123"


@pytest.fixture
def owners(monkeypatch):
    """In-memory stand-in for the Redis owner map."""
    from api.routes import hunt
    store = {}
    monkeypatch.setattr(hunt, "_remember_owner", lambda t, u: store.__setitem__(t, u))
    monkeypatch.setattr(hunt, "_owner_of", lambda t: store.get(t))
    return store


async def test_hunt_query_requires_auth(client_no_auth):
    r = await client_no_auth.post("/api/v1/hunt/query", json={"query": "test"})
    assert r.status_code in (401, 403)


async def test_hunt_query_read_only_denied(client_read_only):
    r = await client_read_only.post("/api/v1/hunt/query", json={"query": "test"})
    assert r.status_code in (401, 403)


async def test_hunt_query_queues_and_records_owner(client_cyber, cyber_user, owners, monkeypatch):
    pytest.importorskip("celery")
    from api.core import tasks
    monkeypatch.setattr(tasks.hunt_investigate, "delay", lambda *a: _Task())
    r = await client_cyber.post("/api/v1/hunt/query", json={"query": "login failures on server001"})
    assert r.status_code == 200 and r.json() == {"task_id": "task-123"}
    assert owners["task-123"] == str(cyber_user.id)


async def test_hunt_query_empty_rejected(client_cyber):
    r = await client_cyber.post("/api/v1/hunt/query", json={"query": ""})
    assert r.status_code == 422


async def test_hunt_query_bad_time_range_rejected(client_cyber):
    r = await client_cyber.post("/api/v1/hunt/query", json={"query": "x", "time_range": "forever"})
    assert r.status_code == 422


async def test_hunt_result_requires_auth(client_no_auth):
    r = await client_no_auth.get("/api/v1/hunt/result/fake-task-id")
    assert r.status_code in (401, 403)


async def test_hunt_result_is_404_for_someone_elses_hunt(client_cyber, owners):
    owners["task-9"] = "some-other-user"
    r = await client_cyber.get("/api/v1/hunt/result/task-9")
    assert r.status_code == 404


async def test_hunt_result_unknown_task_is_404(client_cyber, owners):
    r = await client_cyber.get("/api/v1/hunt/result/does-not-exist")
    assert r.status_code == 404


async def test_hunt_result_failure_is_generic(client_cyber, cyber_user, owners, monkeypatch):
    pytest.importorskip("celery")
    from api.core import tasks

    class _Boom:
        state = "FAILURE"
        result = RuntimeError("db password is hunter2")

    owners["t1"] = str(cyber_user.id)
    monkeypatch.setattr(tasks.celery_app, "AsyncResult", lambda _id: _Boom())
    r = await client_cyber.get("/api/v1/hunt/result/t1")
    assert r.status_code == 200 and "hunter2" not in r.text


async def test_hunt_result_shows_progress_stage(client_cyber, cyber_user, owners, monkeypatch):
    pytest.importorskip("celery")
    from api.core import tasks

    class _Busy:
        state = "PROGRESS"
        info = {"stage": "Following the leads"}

    owners["t2"] = str(cyber_user.id)
    monkeypatch.setattr(tasks.celery_app, "AsyncResult", lambda _id: _Busy())
    assert (await client_cyber.get("/api/v1/hunt/result/t2")).json() == {"status": "running", "stage": "Following the leads"}


async def test_hunt_search_rejects_writing_spl(client_cyber, owners):
    r = await client_cyber.post("/api/v1/hunt/search", json={"spl": "index=main | delete"})
    assert r.status_code == 400


async def test_catalog_has_no_hardcoded_windows():
    from api.hunt.catalog import build_spl_catalog
    for item in build_spl_catalog([{"name": "wineventlog"}, {"name": "_internal"}]):
        assert "earliest=" not in item["spl"] and "inputlookup" not in item["spl"]
        assert "_internal" not in item["spl"]
