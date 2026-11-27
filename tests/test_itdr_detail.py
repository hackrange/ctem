"""ITDR alerts: an Okta ThreatInsight attack is one alert with a count (its repeats kept, resolved and pointing at it),
and every alert opens in full (IP, country, the provider's verdict and reason) for cyber and admin only, showing
known fields of the raw event and nothing else."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

T0 = datetime(2026, 11, 27, 15, 0, tzinfo=timezone.utc)


def _spray(ip, at, reason="Password Spray, Login Failures"):
    from api.models.identity import IdentityThreat, ItdrAlertStatus, ItdrThreatType
    return IdentityThreat(source="okta", external_id=str(uuid.uuid4()), threat_type=ItdrThreatType.brute_force, severity="medium",
                          status=ItdrAlertStatus.active, title="Request from suspicious actor", mitre_technique_id="T1110",
                          source_ip=ip, country="United States", detected_at=at, app_name="Okta",
                          raw={"eventType": "security.threat.detected", "outcome": {"result": "DENY", "reason": reason},
                               "reason": reason, "asOrg": "acme hosting", "isProxy": False, "zone": "null",
                               "userAgent": "Mozilla/5.0", "secret_field": {"nested": "never shown"}})


@pytest.mark.asyncio
async def test_repeats_of_one_attack_are_one_alert_with_a_count(db):
    from api.integrations.okta_signals import merge_repeats
    from api.models.identity import IdentityThreat, ItdrAlertStatus
    ip, other = f"198.51.100.{uuid.uuid4().int % 250}", "203.0.113.7"
    rows = [_spray(ip, T0 + timedelta(seconds=s)) for s in (0, 2, 5)]                  # one spray, three blocked requests
    rows += [_spray(ip, T0 + timedelta(days=3))]                                        # days later: a new alert
    rows += [_spray(other, T0), _spray(ip, T0, reason="Login Failures")]                # another IP, another reason
    db.add_all(rows)
    await db.commit()
    assert await merge_repeats(db) == 2
    assert await merge_repeats(db) == 0                                                 # safe to run again
    got = {t.id: t for t in (await db.execute(select(IdentityThreat).where(IdentityThreat.id.in_([r.id for r in rows]))
                                              .execution_options(populate_existing=True))).scalars()}
    first, a, b, later = (got[r.id] for r in rows[:4])
    assert first.status == ItdrAlertStatus.active and first.raw["count"] == 3
    assert first.raw["last_seen"].startswith((T0 + timedelta(seconds=5)).isoformat()[:19])
    assert a.status == b.status == ItdrAlertStatus.resolved and a.raw["merged_into"] == str(first.id)   # kept, not deleted
    assert later.status == ItdrAlertStatus.active and later.raw["count"] == 1
    assert all(got[r.id].status == ItdrAlertStatus.active for r in rows[4:])
    await db.execute(delete(IdentityThreat).where(IdentityThreat.id.in_([r.id for r in rows])))
    await db.commit()


@pytest.mark.asyncio
async def test_an_alert_opens_with_what_happened_for_cyber_and_admin_only(db, client_cyber, client_it_user, client_read_only):
    from api.models.identity import IdentityThreat
    t = _spray("192.0.2.10", T0)
    t.raw = {**t.raw, "count": 12, "last_seen": (T0 + timedelta(minutes=3)).isoformat()}
    db.add(t)
    await db.commit()
    for c in (client_it_user, client_read_only):
        assert (await c.get(f"/api/v1/identity/threats/{t.id}")).status_code in (401, 403, 404)
    d = (await client_cyber.get(f"/api/v1/identity/threats/{t.id}")).json()
    assert d["source_ip"] == "192.0.2.10" and d["country"] == "United States" and d["count"] == 12
    assert d["details"]["reason"] == "Password Spray, Login Failures" and d["details"]["outcome"] == "DENY"
    assert d["details"]["asOrg"] == "acme hosting" and "zone" not in d["details"]        # Okta's literal "null" isn't shown
    assert "secret_field" not in d["details"] and "never shown" not in str(d)            # known fields only
    assert (await client_cyber.get(f"/api/v1/identity/threats/{uuid.uuid4()}")).status_code == 404
    listed = (await client_cyber.get("/api/v1/identity/threats")).json()["threats"]
    assert next(x for x in listed if x["id"] == str(t.id))["count"] == 12
    await db.execute(delete(IdentityThreat).where(IdentityThreat.id == t.id))
    await db.commit()
