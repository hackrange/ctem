"""Curated rule hits weighed against what CTEM knows: the tool's own severity, new or established, what people
already decided, and how it spread. Routine activity drops below the watch's bar; intrusion-shaped spread stays high."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from api.hunt.context import explain, weigh

NOW = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)
SINCE = NOW - timedelta(days=7)
T = "ApplicationAbusePreventionRemoteMonitoringAndManagement"


def a(days_ago, host, person=None, sev="informational", status="new", title=T, hours=0):
    return {"title": title, "source": "crowdstrike", "hostname": host, "user_key": person, "severity": sev, "status": status,
            "detected_at": (NOW - timedelta(days=days_ago, hours=hours)).isoformat()}


def test_a_developer_tool_people_use_on_their_own_machines_is_routine():
    old = [a(25 - i, f"ws{i % 3}", f"p{i % 3}", status="closed") for i in range(10)]      # since four weeks, mostly closed
    hits = [a(1, "ws0", "p0"), a(1, "ws3", "p3", hours=3), a(0, "ws4", "p4"), a(0, "ws5", "p5")]   # three people joined
    c = weigh(hits, old + hits, SINCE, NOW)
    assert c["confidence"] == "low" and not c["escalated"]
    text = explain(c)
    assert "informational" in text and "10 of 14 already closed in CrowdStrike" in text and "4 people, each on their own machine" in text


def test_one_account_across_hosts_stays_high_whatever_else_says():
    old = [a(25 - i, f"ws{i}", f"p{i}", status="closed") for i in range(10)]
    hits = [a(0, f"srv{i}", "svc-admin", hours=i) for i in range(4)]
    c = weigh(hits, old + hits, SINCE, NOW)
    assert c["confidence"] == "high" and c["escalated"] and "one account on 4 hosts" in explain(c)


def test_a_new_detection_reaching_hosts_fast_stays_high():
    hits = [a(0, f"ws{i}", f"p{i}", sev="high", hours=i) for i in range(4)]
    c = weigh(hits, hits, SINCE, NOW)
    assert c["confidence"] == "high" and "reached 4 new hosts within 48 hours" in explain(c) and "new here" in explain(c)


def test_the_tools_own_severity_caps_confidence():
    assert weigh([a(0, "h1", sev="low", title="X")], [], SINCE, NOW)["confidence"] == "medium"
    assert weigh([a(0, "h1", sev="informational", title="X")], [], SINCE, NOW)["confidence"] == "low"
    assert weigh([a(0, "h1", sev="high", title="X")], [], SINCE, NOW)["confidence"] == "high"
    assert explain(weigh([a(0, "h1", sev="high", title="X")], [a(0, "h1", sev="high", title="X")], SINCE, NOW)).startswith(" Kept")


def test_established_and_closed_each_step_down():
    old = [a(30 - i, "h1", sev="high", status="closed" if i < 8 else "new", title="Y") for i in range(10)]
    c = weigh([a(0, "h1", sev="high", title="Y")], old, SINCE, NOW)
    assert c["confidence"] == "low" and "seen steadily since" in explain(c) and "8 of 10 already closed" in explain(c)
