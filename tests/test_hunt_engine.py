"""Hunt internals: the SPL gate, data allowlist, AI output cleanup, and token reuse."""
from __future__ import annotations

import json

import pytest

from api.hunt import ai as hunt_ai
from api.hunt import ctem_data, engine, fallback, memory
from api.hunt.results import splunk_table
from api.hunt.spl_guard import quote_value, vet_spl


@pytest.mark.parametrize("spl", [
    "index=main | delete", "index=main | outputlookup x.csv", "index=main | sendemail to=a@b.c",
    "| rest /services/authentication/users", "index=main [search index=x | fields host]",
    "index=main `evil_macro`", "index=main | map search=\"search index=x\"", "index=main | script python x",
    "index=main | collect index=summary", "", "x" * 2001,
    "index=* EventCode=4625", "EventCode=4625 | stats count", "index=win* EventCode=4625",
    "index IN (main, *) x", 'index="*" x',
])
def test_spl_gate_blocks_anything_that_is_not_read_only(spl):
    with pytest.raises(ValueError):
        vet_spl(spl)


def test_spl_gate_allows_and_caps_reads():
    out = vet_spl('index=wineventlog EventCode=4625 | stats count by TargetUserName | sort -count')
    assert out.startswith("search index=wineventlog") and out.endswith("| head 200")
    assert vet_spl('search index=x "a | delete"').startswith('search index=x "a | delete"')


def test_quote_value_escapes():
    assert quote_value('a"b\\c') == '"a\\"b\\\\c"'


def test_ctem_allowlist_has_no_secret_fields():
    blob = json.dumps({k: [list(v[1]), list(v[2])] for k, v in ctem_data.TABLES.items()}).lower()
    for secret in ("password", "totp", "token", "secret", "api_key", "email", "recovery", "config"):
        assert secret not in blob


def test_ctem_rejects_unknown_tables_and_filters():
    with pytest.raises(ValueError):
        ctem_data.validate("api_tokens", {})
    with pytest.raises(ValueError):
        ctem_data.validate("users", {"password_hash": "x"})


def test_write_up_cleanup_bounds_everything():
    raw = {"summary": "s" * 5000, "issues": [
        {"title": "t", "severity": "apocalyptic", "confidence": "?", "timeline": [{"time": "x", "lookup": 99}],
         "lookups": [1, 7, "x"], "involved": {"hosts": ["h"] * 40}},
        {"title": "c", "severity": "critical"}, "junk"]}
    out = hunt_ai.clean_write_up(raw, n_lookups=3)
    assert len(out["summary"]) == 1200
    assert [i["severity"] for i in out["issues"]] == ["critical", "medium"]
    assert out["issues"][1]["lookups"] == [1] and out["issues"][1]["timeline"][0]["lookup"] is None
    assert len(out["issues"][1]["involved"]["hosts"]) == 15


def test_attack_ids_validated_and_links_built_server_side():
    out = hunt_ai._attack([{"id": "t1003.001", "name": "LSASS"}, {"id": "javascript:alert(1)"},
                           {"id": "T99"}, "junk"])
    assert out == [{"id": "T1003.001", "name": "LSASS", "plain": "",
                    "url": "https://attack.mitre.org/techniques/T1003/001/"}]


def test_extract_json_handles_fences():
    assert hunt_ai._extract_json('Sure!\n```json\n{"a": 1}\n```') == {"a": 1}


def test_splunk_rows_are_tidied():
    cols, rows = splunk_table([{"_time": "2026-11-16T02:15:02.000+00:00", "_bkt": "x", "_cd": "1",
                                "host": "h1", "first_seen": "1794795302", "punct": "{::}"}])
    assert cols[0] == "time" and "_bkt" not in cols and "punct" not in cols
    assert rows[0]["time"] == "2026-11-16 02:15:02" and rows[0]["first_seen"].startswith("2026-")


SCHEMA = {"indexes": {
    "wineventlog": {"type_field": "EventCode", "types": {"4624": 15000, "4625": 157, "4740": 9},
                    "fields": {"TargetUserName": {}, "IpAddress": {}, "host": {}, "WorkstationName": {}}},
    "crowdstrike": {"type_field": "event_simpleName", "types": {"ProcessRollup2": 17000, "DetectionSummaryEvent": 1},
                    "fields": {"ComputerName": {}, "UserName": {}, "host": {}, "aip": {}}},
    "guardicore": {"type_field": "event_type", "types": {"network_flow": 28000, "incident": 3},
                   "fields": {"source_asset": {}, "destination_asset": {}, "host": {}}}}}


def test_fallback_picks_intents_and_entities():
    plan = fallback.plan("Is someone guessing passwords for user jsmith on ACME-WS-023?", SCHEMA)
    titles = [p["title"] for p in plan]
    assert "Password guessing and lockouts" in titles
    assert any("ACME-WS-023" in t for t in titles) and any("jsmith" in t for t in titles)
    for p in plan:
        if p["source"] == "splunk":
            vet_spl(p["spl"])


def test_plan_key_ignores_case_and_punctuation():
    assert memory.plan_key("What happened on WS-1?") == memory.plan_key("what happened on ws-1")


class _FakeAI:
    def __init__(self):
        self.calls = []

    async def complete(self, prompt, **kw):
        self.calls.append(prompt)
        if "Plan up to 6" in prompt:
            return json.dumps({"lookups": [
                {"source": "splunk", "title": "Detections", "why": "EDR", "spl": "search index=crowdstrike | table _time ComputerName"},
                {"source": "ctem", "title": "Devices", "why": "assets", "table": "devices", "filters": {"hostname": "WS*"}},
                {"source": "splunk", "title": "Bad", "why": "nope", "spl": "index=x | delete"}]})
        if "follow-up" in prompt:
            return json.dumps({"lookups": []})
        return json.dumps({"summary": "One machine had passwords stolen.", "issues": [
            {"title": "Password theft on WS-33", "severity": "critical", "confidence": "high",
             "what_happened": "A tool grabbed passwords.", "timeline": [{"time": "2026-11-16 02:15", "source": "CrowdStrike", "what": "Stole passwords", "lookup": 1}],
             "what_to_do": ["Unplug it"], "lookups": [1]}]})


class _FakeSplunk:
    async def run_search(self, spl, earliest="-7d", latest="now", max_rows=200):
        assert "delete" not in spl
        return [{"_time": "2026-11-16T02:15:02.000+00:00", "ComputerName": "ACME-WS-033"}]


class _Cfg:
    config = {}


async def test_hunt_end_to_end_and_reuses_plan(db, monkeypatch):
    fake = _FakeAI()

    async def enabled(_db, vendors, live=False):
        return [_Cfg()] if "splunk" in vendors else []

    async def get_ai(_db):
        return fake

    async def schema(_db):
        return {"indexes": {"crowdstrike": {"fingerprint": "f1", "fields": {}}}}

    monkeypatch.setattr(engine, "_enabled", enabled)
    monkeypatch.setattr(hunt_ai, "get_ai", get_ai)
    monkeypatch.setattr(engine, "load_schema", schema)
    monkeypatch.setattr("api.integrations.base.get_connector", lambda v, c: _FakeSplunk())

    first = await engine.investigate(db, "Was anything stolen on WS-33?", "7d")
    assert first["mode"] == "ai" and first["issues"][0]["severity"] == "critical"
    pinned = first["issues"][0]["splunk"][0]
    assert pinned.startswith("search earliest=") and "index=crowdstrike" in pinned and "head 200" not in pinned
    assert first["issues"][0]["window_label"].startswith("Nov 16 01:45")
    assert any("Skipped 'Bad'" in n for n in first["notes"])
    planned = sum("Plan up to 6" in c for c in fake.calls)

    second = await engine.investigate(db, "was anything stolen on ws-33", "7d")
    assert sum("Plan up to 6" in c for c in fake.calls) == planned  # no new planning tokens
    assert any("Reused saved searches" in n for n in second["notes"])
    learned = await memory.learned_searches(db)
    assert any(item["title"] == "Detections" for item in learned)

    # The dashboard watch's alerts lookup runs even on a reused plan, and is never saved into it
    from api.hunt.watch import ALWAYS
    third = await engine.investigate(db, "was anything stolen on ws-33", "7d", always=ALWAYS)
    assert any("Reused saved searches" in n for n in third["notes"])
    assert any(lk.get("title") == "Recent alerts from every connected tool" for lk in third["lookups"])
    assert not any(item["title"] == "Recent alerts from every connected tool" for item in await memory.learned_searches(db))


async def test_ai_connector_reads_text_after_a_thinking_block(monkeypatch):
    from api.integrations import ai_connector

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"content": [{"type": "thinking", "thinking": "hmm"}, {"type": "text", "text": '{"ok": 1}'}]}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(ai_connector, "safe_client", lambda **k: _Client())
    conn = ai_connector._AnthropicConnector({"api_key": "x"})
    assert await conn.complete("hi") == '{"ok": 1}'


def test_spl_gate_allows_named_and_correlated_indexes():
    vet_spl("(index=wineventlog OR index=crowdstrike) host=x")
    vet_spl("index IN (wineventlog, guardicore) host=x")


def test_every_generated_search_names_its_indexes():
    from api.hunt.catalog import build_spl_catalog
    idx = [{"name": n, "totalEventCount": 5} for n in SCHEMA["indexes"]]
    items = build_spl_catalog(idx, SCHEMA)
    plans = fallback.plan("failed passwords for user jsmith on ACME-WS-023 and 10.10.20.23", SCHEMA)
    spls = [i["spl"] for i in items] + [p["spl"] for p in plans if p["source"] == "splunk"]
    assert spls
    for spl in spls:
        assert "index=*" not in spl
        vet_spl(spl)
    lockouts = next(i for i in items if i["title"] == "Password guessing and lockouts")
    assert lockouts["spl"].startswith("index=wineventlog ")


def test_notable_clause_skips_routine_firehose():
    from api.hunt.scope import notable_clause
    clause = notable_clause(SCHEMA)
    assert '"4625"' in clause and '"DetectionSummaryEvent"' in clause and '"incident"' in clause
    assert '"4624"' not in clause and "network_flow" not in clause


def test_window_pads_thirty_minutes_each_side():
    from api.hunt import window
    win = window.around(["2026-11-16 02:15", "2026-11-16 03:00:00", "garbage"])
    assert window.label(win) == "Nov 16 01:45 to 03:30 UTC"
    assert window.for_splunk("search index=x a | head 200", win) == f"search earliest={win[0]} latest={win[1]} index=x a"
    assert window.around(["nope"]) is None


def test_watch_only_keeps_serious_findings():
    from api.hunt.watch import worth_showing
    two = [{"source": "CrowdStrike"}, {"source": "Guardicore"}]
    one = [{"source": "Windows"}, {"source": "windows"}]
    assert worth_showing({"severity": "critical", "confidence": "medium", "timeline": one})
    assert not worth_showing({"severity": "critical", "confidence": "low", "timeline": two})
    assert worth_showing({"severity": "high", "confidence": "medium", "timeline": two})
    assert not worth_showing({"severity": "high", "confidence": "medium", "timeline": one})
    assert worth_showing({"severity": "medium", "confidence": "high", "timeline": two})
    assert not worth_showing({"severity": "medium", "confidence": "high", "timeline": one})
    assert not worth_showing({"severity": "low", "confidence": "high", "timeline": two})


async def test_watch_requires_cyber(client_read_only):
    assert (await client_read_only.get("/api/v1/hunt/watch")).status_code == 403


async def test_profile_rejects_bad_input(client_cyber):
    assert (await client_cyber.post("/api/v1/hunt/profile", json={"kind": "file", "value": "x"})).status_code == 422
    assert (await client_cyber.post("/api/v1/hunt/profile", json={"kind": "ip", "value": "not-an-ip"})).status_code == 400
    assert (await client_cyber.post("/api/v1/hunt/profile", json={"kind": "user", "value": 'a" OR index=*'})).status_code == 400


def test_ticket_text_is_plain_and_escaped():
    from api.hunt.handoff import ticket_text
    issue = {"severity": "critical", "confidence": "high", "title": "Bad <b>thing</b>", "what_happened": "x",
             "why_it_matters": "y", "timeline": [{"time": "t", "source": "s", "what": "<script>"}],
             "involved": {"hosts": ["h"], "users": [], "ips": []}, "attack": [], "what_to_do": ["do it"]}
    subject, plain, html_body = ticket_text(issue)
    assert subject.startswith("[open-ctem] [CRITICAL]")
    assert "<script>" in plain and "<script>" not in html_body and "&lt;script&gt;" in html_body


async def test_ticket_and_report_404_for_someone_elses_hunt(client_cyber, monkeypatch):
    from api.routes import hunt
    monkeypatch.setattr(hunt, "_owner_of", lambda t: "someone-else")
    r = await client_cyber.post("/api/v1/hunt/ticket", json={"source": "abc-123", "issue": 0, "method": "email"})
    assert r.status_code == 404
    assert (await client_cyber.get("/api/v1/hunt/report/abc-123/0")).status_code == 404


async def test_ticket_rejects_bad_source(client_cyber):
    r = await client_cyber.post("/api/v1/hunt/ticket", json={"source": "../../x", "issue": 0, "method": "api"})
    assert r.status_code == 422
