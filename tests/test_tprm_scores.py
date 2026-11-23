"""Vendor security score history and the quarter-by-quarter KPI."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from api.core import tprm_scores as ts
from api.dashboards import catalog as cat
from api.dashboards import fleet

UTC = timezone.utc
cat.load_metrics()


def test_combined_score_matches_fairtprm():
    assert ts.combined([812 / 950 * 100, 77, None]) == 81        # (85.47 + 77) / 2 = 81.24
    assert ts.combined([50.0, 51.0]) == 51                         # 50.5 rounds half up, like PHP round()
    assert ts.combined([0, None]) is None                          # parts at 0 don't count
    pts = [("upguard", 80.0, datetime(2026, 3, 1, tzinfo=UTC)), ("upguard", 90.0, datetime(2026, 5, 1, tzinfo=UTC)),
           ("custom", 60.0, datetime(2026, 2, 1, tzinfo=UTC)), ("custom", None, datetime(2026, 4, 1, tzinfo=UTC)),
           ("combined", 10.0, datetime(2026, 1, 15, tzinfo=UTC))]
    assert ts.score_at(pts, datetime(2026, 1, 20, tzinfo=UTC)) == 10      # only the daily record so far
    assert ts.score_at(pts, datetime(2026, 3, 31, tzinfo=UTC)) == 70      # upguard 80 and custom 60
    assert ts.score_at(pts, datetime(2026, 6, 30, tzinfo=UTC)) == 90      # custom cleared in April
    assert ts.score_at(pts, datetime(2025, 12, 31, tzinfo=UTC)) is None


@pytest.mark.asyncio
async def test_history_ingest_and_the_quarter_card(db, admin_user, monkeypatch):
    from api.models.risk import ThirdPartyRisk
    n = uuid.uuid4().hex[:6]
    a = ThirdPartyRisk(source="fairtprm", external_id=f"9{int(n, 16) % 99999}", supplier_name=f"Acme Payroll {n}", tier="tier1")
    b = ThirdPartyRisk(source="fairtprm", external_id=f"8{int(n, 16) % 99999}", supplier_name=f"Acme Cloud {n}", tier="tier1")
    db.add_all([a, b])
    await db.commit()
    page = {"timezone": "America/New_York", "upguard_max_score": 1000, "data": [
        {"id": int(a.external_id), "upguard": [{"score": 700, "scored_at": "2026-03-30 23:00:00"}],   # Mar 31 04:00 UTC
         "shodan": [{"score": 90, "scored_at": "2026-06-01 10:00:00"}], "custom": []},
        {"id": int(b.external_id), "upguard": [{"score": 900, "scored_at": "2026-02-01 00:00:00"}, {"score": "bad", "scored_at": "x"}],
         "shodan": [], "custom": [{"score": 50, "changed_at": "2026-05-01 00:00:00"}]}]}
    sup = {a.external_id: str(a.id), b.external_id: str(b.id)}
    assert await ts.ingest(db, page, sup) == 4
    assert await ts.ingest(db, page, sup) == 0                     # nothing twice
    await db.commit()
    monkeypatch.setattr(fleet, "now", lambda: datetime(2026, 11, 23, 12, tzinfo=UTC))
    ctx = await cat.context(db, admin_user)
    m = cat.REGISTRY["tprm.score_quarter"]
    run = lambda **p: m.run(ctx, {q.key: q.clean(p.get(q.key)) for q in m.params})  # noqa: E731
    one = await run(quarter="q1", vendor=f"acme payroll {n}")
    assert one["value"] == 70.0 and "as of Mar 31" in one["note"]
    two = await run(quarter="q2", vendor=f"Payroll {n}")           # part of the name, one match
    assert two["value"] == 80.0 and two["delta"] == {"pct": 14.3, "was": 70.0, "better": "up"}
    amb = await run(quarter="q2", vendor=f"Acme ")
    assert amb["value"] is None and "use the full name" in amb["note"]
    assert "No vendor matches" in (await run(quarter="q2", vendor="Nobody Inc"))["note"]
    mine = [a, b]
    from sqlalchemy import update
    await db.execute(update(ThirdPartyRisk).where(ThirdPartyRisk.tier == "tier1", ThirdPartyRisk.id.not_in([x.id for x in mine]))
                     .values(tier="tier1_other_tests"))
    await db.commit()
    t1 = await run(quarter="q2", tier="tier1")
    assert t1["value"] == round((80 + 70) / 2, 1) and "average of 2 scored vendors" in t1["note"]   # b: (90 + 50) / 2
    q4 = await run(quarter="current", tier="tier1")                # November: Q4 so far, as of today
    assert q4["value"] == 75.0 and "so far (today)" in q4["note"]
    monkeypatch.setattr(fleet, "now", lambda: datetime(2026, 2, 1, tzinfo=UTC))
    assert "hasn't started" in (await run(quarter="q3", tier="tier1"))["note"]


def test_vendor_option_is_text_and_checked():
    p = cat.REGISTRY["tprm.score_quarter"].params[-1]
    assert p.spec()["type"] == "text" and p.clean("  Acme Payroll ") == "Acme Payroll" and len(p.clean("x" * 200)) == 128
    assert p.clean("drop table; --") == "" and p.clean(None) == ""


@pytest.mark.asyncio
async def test_without_the_history_endpoint_today_is_recorded_once(db):
    from sqlalchemy import select

    from api.integrations.fairtprm import FairTPRMError
    from api.integrations.fairtprm_scores import sync_scores
    from api.models.risk import ThirdPartyRisk, ThirdPartyScore
    n = uuid.uuid4().hex[:6]
    v = ThirdPartyRisk(source="fairtprm", external_id=f"7{int(n, 16) % 99999}", supplier_name=f"Acme Mail {n}", tier="tier2")
    db.add(v)
    await db.commit()
    await db.execute(ThirdPartyScore.__table__.delete().where(ThirdPartyScore.kind == "combined"))
    await db.commit()

    class Conn:
        calls = 0

        async def _get(self, client, path, params=None):
            Conn.calls += 1
            if path == "/vendors/score-history":
                raise FairTPRMError("FairTPRM returned HTTP 404", 404)
            return {"data": {"current_srs_score": 760, "current_shodan_score": 70, "custom_score": None}}
    assert await sync_scores(Conn(), None, db) >= 1
    row = (await db.execute(select(ThirdPartyScore).where(ThirdPartyScore.supplier_id == v.id))).scalar_one()
    assert row.kind == "combined" and row.score == 75.0          # (760 / 950 * 100 + 70) / 2
    before = Conn.calls
    assert await sync_scores(Conn(), None, db) == 0               # once a day
    assert Conn.calls == before + 1                               # only the history check
