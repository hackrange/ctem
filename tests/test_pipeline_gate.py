"""One post-sync pipeline at a time (api/core/pipeline_gate.py), and enrichment asks FIRST only for what's due."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest


class _Redis:
    """Enough of Redis for the gate: SET NX, GETDEL, EXISTS, EXPIRE and its two scripts."""

    def __init__(self):
        self.kv = {}

    def set(self, k, v, nx=False, ex=None):
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        return True

    def getdel(self, k):
        return self.kv.pop(k, None)

    def exists(self, k):
        return int(k in self.kv)

    def expire(self, k, ttl):
        return True

    def eval(self, script, n, key, *args):
        from api.core import pipeline_gate as gate
        if script == gate._QUEUE:
            cur, new = self.kv.get(key), args[0]
            if cur != "full" and (new == "full" or cur is None or new < cur):
                self.kv[key] = new
            return 1
        if self.kv.get(key) == args[0]:
            del self.kv[key]
            return 1
        return 0


def test_runs_one_at_a_time_and_takes_up_what_waited(monkeypatch):
    import api.core.tasks as tasks
    from api.core import pipeline_gate as gate
    r, ran, later = _Redis(), [], []
    monkeypatch.setattr(gate, "client", lambda: r)
    monkeypatch.setattr(tasks.post_sync_pipeline, "apply_async", lambda *a, **k: later.append((a, k)))

    def pipeline(since):
        ran.append(since)
        if len(ran) == 1:   # two syncs finish while the first run is going: they wait, earliest window first
            tasks.post_sync_pipeline.run("2026-11-25T18:30:00+00:00")
            tasks.post_sync_pipeline.run("2026-11-25T18:10:00+00:00")
    monkeypatch.setattr(tasks, "_pipeline", pipeline)
    tasks.post_sync_pipeline.run("2026-11-25T18:00:00+00:00")
    assert ran == ["2026-11-25T18:00:00+00:00", "2026-11-25T18:10:00+00:00"]   # never two at once; one catch-up run
    assert gate.RUNNING not in r.kv and gate.PENDING not in r.kv and not later
    # a full rescore asked for while one runs wins over any window
    ran.clear()

    def pipeline2(since):
        ran.append(since)
        if len(ran) == 1:
            tasks.post_sync_pipeline.run("2026-11-25T19:00:00+00:00")
            tasks.post_sync_pipeline.run(None)
    monkeypatch.setattr(tasks, "_pipeline", pipeline2)
    tasks.post_sync_pipeline.run("2026-11-25T18:55:00+00:00")
    assert ran == ["2026-11-25T18:55:00+00:00", None]


def test_a_failed_run_keeps_its_window_and_retries_after_a_pause(monkeypatch):
    import api.core.tasks as tasks
    from api.core import pipeline_gate as gate
    r, later = _Redis(), []
    monkeypatch.setattr(gate, "client", lambda: r)
    monkeypatch.setattr(tasks.post_sync_pipeline, "apply_async", lambda *a, **k: later.append(k.get("countdown")))

    def boom(since):
        raise RuntimeError("database went away")
    monkeypatch.setattr(tasks, "_pipeline", boom)
    with pytest.raises(RuntimeError):
        tasks.post_sync_pipeline.run("2026-11-25T18:00:00+00:00")
    assert r.kv.get(gate.PENDING) == "2026-11-25T18:00:00+00:00" and gate.RUNNING not in r.kv   # kept, lock let go
    assert later == [300]   # tried again after a pause, not in a spin


def test_without_redis_it_just_runs(monkeypatch):
    import api.core.tasks as tasks
    from api.core import pipeline_gate as gate
    ran = []
    monkeypatch.setattr(gate, "client", lambda: None)
    monkeypatch.setattr(tasks, "_pipeline", ran.append)
    tasks.post_sync_pipeline.run("x")
    assert ran == ["x"]


@pytest.mark.asyncio
async def test_epss_is_asked_once_a_day_and_only_moved_scores_mark(db):
    from sqlalchemy import select

    from api.enrichment.kev_epss import _epss_due, apply_epss
    from api.models.vuln import Vulnerability
    t = str(uuid.uuid4().int % 10**5).zfill(5)   # CVE ids are digits
    fresh_cve, stale_cve, new_cve = (f"CVE-2026-{t}{i}" for i in (1, 2, 3))
    now = datetime.now(timezone.utc)
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    db.add_all([Vulnerability(source="t_epss", source_vuln_id=f"a{t}", title="a", cve_id=fresh_cve, epss_score=0.5,
                              epss_updated_at=now, score_inputs_at=past),
                Vulnerability(source="t_epss", source_vuln_id=f"b{t}", title="b", cve_id=stale_cve, epss_score=0.2,
                              epss_updated_at=now - timedelta(days=2), score_inputs_at=past),
                Vulnerability(source="t_epss", source_vuln_id=f"c{t}", title="c", cve_id=new_cve)])
    await db.commit()
    from sqlalchemy import update   # new rows are marked changed; start from "nothing to rescore"
    await db.execute(update(Vulnerability).where(Vulnerability.source == "t_epss").values(score_inputs_at=past))
    await db.commit()
    due = await _epss_due(db, [fresh_cve, stale_cve, new_cve])
    assert set(due) == {stale_cve, new_cve}   # the one refreshed today isn't asked again
    await apply_epss(db, {stale_cve: 0.2, new_cve: 0.9}, due)   # stale one's score didn't move
    rows = {c: (e, m) for c, e, m in (await db.execute(select(Vulnerability.cve_id, Vulnerability.epss_score,
                                                              Vulnerability.score_inputs_at)
                                                       .where(Vulnerability.source == "t_epss")
                                                       .execution_options(populate_existing=True))).all()}

    def at(x):
        return x if x is None or x.tzinfo else x.replace(tzinfo=timezone.utc)
    assert at(rows[stale_cve][1]) == past                       # same score: nothing to rescore
    assert rows[new_cve][0] == 0.9 and at(rows[new_cve][1]) > past
    assert set(await _epss_due(db, [fresh_cve, stale_cve, new_cve])) == set()   # all asked today
