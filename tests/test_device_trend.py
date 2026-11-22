"""An asset's trend: open findings per day from first found until fixed, and its daily risk score."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

from api.models.vuln import FindingStatus
from api.routes.device_trend import series

NOW = datetime.now(timezone.utc)


def test_series_counts_each_day_a_finding_was_open():
    start, end = date(2026, 11, 1), date(2026, 11, 10)
    rows = [(datetime(2026, 10, 20, tzinfo=timezone.utc), None, FindingStatus.open, 9.8),           # open the whole time
            (datetime(2026, 11, 3, tzinfo=timezone.utc), datetime(2026, 11, 6, tzinfo=timezone.utc), FindingStatus.remediated, 7.5),
            (datetime(2026, 11, 8, tzinfo=timezone.utc), None, FindingStatus.in_progress, 4.0),
            (datetime(2026, 11, 2, tzinfo=timezone.utc), None, FindingStatus.false_positive, 9.0)]   # never counts
    s = series(rows, start, end)
    assert len(s["days"]) == 10 and s["days"][0] == "2026-11-01"
    assert s["open"] == [1, 1, 2, 2, 2, 1, 1, 2, 2, 2]        # fixed one counts Nov 3 to 5, gone from its last sighting
    assert s["critical"] == [1] * 10 and s["high"] == [0, 0, 1, 1, 1, 0, 0, 0, 0, 0]


@pytest.mark.asyncio
async def test_trend_endpoint_scopes_and_scores(db, client_admin, client_it_user):
    from api.models.device import Device, DeviceType
    from api.models.risk import RiskScoreHistory
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    d = Device(hostname=f"trend-{n}", device_type=DeviceType.server)
    v = Vulnerability(source="test", source_vuln_id=f"t-{n}", title="t", cvss_base=9.8)
    db.add_all([d, v])
    await db.flush()
    db.add(Finding(device_id=d.id, vuln_id=v.id, source="test", first_detected=NOW - timedelta(days=10)))
    db.add(RiskScoreHistory(entity_type="device", entity_id=str(d.id), score=55.5, grade="C", recorded_at=NOW - timedelta(days=1)))
    await db.commit()
    t = (await client_admin.get(f"/api/v1/devices/{d.id}/trend")).json()
    assert t["range_days"] == 30 and len(t["open"]) == 30 and t["open"][-1] == 1 and t["open"][0] == 0
    assert t["score"][-2] == 55.5 and t["score"][0] is None
    assert len((await client_admin.get(f"/api/v1/devices/{d.id}/trend", params={"days": 90})).json()["days"]) == 90
    assert (await client_admin.get(f"/api/v1/devices/{d.id}/trend", params={"days": 2})).status_code == 422
    assert (await client_it_user.get(f"/api/v1/devices/{d.id}/trend")).status_code == 404      # not theirs
    assert (await client_admin.get(f"/api/v1/devices/{uuid.uuid4()}/trend")).status_code == 404
