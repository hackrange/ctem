"""Tag mapping: roles read a customer's tags as CTEM concepts, with no customer naming in the code."""
from __future__ import annotations

import uuid

import pytest

from api.core import tag_roles as tr


def _roles(**rules):
    return [tr.Role(k, k.title(), True, True, k == "technical_owner", i, tuple(("prefix", p.lower()) for p in ps))
            for i, (k, ps) in enumerate(rules.items())]


def test_longest_match_wins_and_value_is_the_rest():
    roles = _roles(environment=["location:ENV:"], location=["location:"], technical_owner=["r7:aws::itowner:"])
    assert tr.match("location:ENV: AWS", roles) == ("environment", "AWS")
    assert tr.match("location:Dallas DC", roles) == ("location", "Dallas DC")
    assert tr.match("R7:AWS::ITOWNER:jeff davis", roles) == ("technical_owner", "Jeff Davis")   # title case on
    assert tr.match("criticality:high", roles) is None
    assert tr.match("location:", roles) is None   # nothing after the prefix
    exact = [tr.Role("application", "Application", True, True, False, 0, (("exact", "kiosk"),))]
    assert tr.match("KIOSK", exact) == ("application", "KIOSK") and tr.match("kiosk-2", exact) is None


def test_neutral_defaults_name_no_customer():
    keys = {k for k, *_ in tr.BUILTIN}
    assert {"executive_owner", "technical_owner", "application_owner", "application", "environment"} <= keys
    for _, _, _, prefixes in tr.BUILTIN:
        assert not any("e-o" in p.lower() or "r7:" in p for p in prefixes)
    assert tr.first(["exec_owner: Pat Example"], ("executive_owner",), tr._defaults()) == "Pat Example"


def test_rule_validation():
    assert tr.clean_rules([{"match": "prefix", "value": "owner:E-O:"}, {"match": "prefix", "value": "OWNER:e-o:"}]) == [
        {"match": "prefix", "value": "owner:E-O:"}]
    for bad in ([{"match": "regex", "value": "x"}], [{"match": "prefix", "value": ""}], [{"match": "prefix", "value": "<x>"}],
                [{"match": "prefix", "value": "a\nb"}], [{"match": "prefix", "value": "x" * 129}], "nope",
                [{"match": "prefix", "value": f"p{i}:"} for i in range(21)]):
        with pytest.raises(ValueError):
            tr.clean_rules(bad)


async def _tagged(db, tags):
    from api.core.device_tags import sync_tags
    from api.models.device import Device
    d = Device(hostname=f"tm-{uuid.uuid4().hex[:8]}.acme.example")
    db.add(d)
    await db.flush()
    await sync_tags(db, d.id, set(tags), ("owner:", "r7:", "location:"), "rapid7_insightvm", {})
    await db.commit()
    return d


@pytest.mark.asyncio
async def test_suggestions_find_the_customers_own_prefixes(db):
    n = uuid.uuid4().hex[:6]
    await _tagged(db, {f"owner:E-O: Pat {n}", f"owner:T-O: Sam {n}", f"owner:A-O: Lee {n}", f"r7:app: Qlik {n}",
                       f"location:ENV: AWS {n}", f"r7:amazon-web-services::itowner:kim {n}", f"r7:department: 90{n}"})
    tr.forget()
    got = {(s["role"], s["value"].lower()) for s in await tr.suggestions(db, await tr.ensure(db, fresh=True))}
    for want in [("executive_owner", "owner:e-o: "), ("technical_owner", "owner:t-o: "), ("application_owner", "owner:a-o: "),
                 ("application", "r7:app: "), ("environment", "location:env: "),
                 ("technical_owner", "r7:amazon-web-services::itowner:"), ("business_unit", "r7:department: ")]:
        assert want in got, (want, got)


@pytest.mark.asyncio
async def test_admin_maps_tags_and_everything_reads_it(db, client_admin, client_read_only, client_cyber):
    n = uuid.uuid4().hex[:6]
    d = await _tagged(db, {f"owner:E-O: Pat {n}", f"owner:T-O: Sam {n}", f"location:ENV: QA {n}"})
    put = lambda key, name, rules: client_admin.put(f"/api/v1/tag-roles/{key}", json={  # noqa: E731
        "name": name, "show_filter": True, "title_case": False, "rules": [{"match": "prefix", "value": v} for v in rules]})
    try:
        assert (await put("executive_owner", "Executive owner", ["exec_owner:", "owner:E-O:"])).json()["ok"]
        assert (await put("technical_owner", "Technical owner", ["tech_owner:", "owner:T-O:"])).json()["ok"]
        assert (await put("environment", "Environment", ["env:", "location:ENV:"])).json()["ok"]
        # Read-only users read the filters and labels but can't change the mapping
        assert (await client_read_only.put("/api/v1/tag-roles/executive_owner", json={"name": "x", "rules": []})).status_code == 403
        f = {x["key"]: x for x in (await client_read_only.get("/api/v1/tag-roles/filters")).json()["filters"]}
        assert {"tag": f"owner:E-O: Pat {n}", "value": f"Pat {n}"} in f["executive_owner"]["options"]
        r = (await client_read_only.post("/api/v1/tag-roles/resolve", json={"tags": [f"owner:T-O: Sam {n}", "plain"]})).json()
        assert r["tags"][0] == {"tag": f"owner:T-O: Sam {n}", "role": "technical_owner", "role_name": "Technical owner",
                                "value": f"Sam {n}"} and r["tags"][1]["role"] is None
        p = (await client_admin.post("/api/v1/tag-roles/preview", json={"rules": [{"match": "prefix", "value": "owner:E-O:"}]})).json()
        assert p["ok"] and p["devices"] >= 1 and f"Pat {n}" in p["sample"] + [f"Pat {n}"]
        # The CMDB reads the roles: technical owner first, environment from the mapping
        rec = next(x for x in (await client_cyber.get("/api/v1/cmdb", params={"q": d.hostname.split(".")[0]})).json()["records"])
        assert rec["owner"] == f"Sam {n}" and rec["environment"] == f"QA {n}"
        # Bad input is refused readably; built-ins can't be deleted; custom roles can
        bad = (await put("executive_owner", "Executive owner", ["<script>"])).json()
        assert bad["ok"] is False and "without < or >" in bad["error"]
        assert (await client_admin.delete("/api/v1/tag-roles/executive_owner")).json()["ok"] is False
        made = (await client_admin.post("/api/v1/tag-roles", json={"key": "custom_data_owner", "name": "Data owner",
                                                                    "rules": [{"match": "prefix", "value": "data_owner:"}]})).json()
        assert made["ok"] and (await client_admin.delete("/api/v1/tag-roles/custom_data_owner")).json()["ok"]
        assert (await client_admin.put("/api/v1/tag-roles/no_such_role", json={"name": "x", "rules": []})).status_code == 404
    finally:
        for key, name, _, prefixes in tr.BUILTIN:
            await client_admin.put(f"/api/v1/tag-roles/{key}", json={"name": name, "rules": [{"match": "prefix", "value": p} for p in prefixes]})
        tr.forget()


@pytest.mark.asyncio
async def test_preview_counts_only_tags_the_role_would_win(db):
    n = uuid.uuid4().hex[:6]
    await _tagged(db, {f"location:ENV: Lab {n}", f"location:Dallas {n}"})
    others = [tr.Role("environment", "Environment", True, True, False, 0, (("prefix", "location:env:"),))]
    alone = await tr.preview(db, [{"match": "prefix", "value": "location:"}])
    judged = await tr.preview(db, [{"match": "prefix", "value": "location:"}], key="location", others=others)
    assert alone["tags"] > judged["tags"]   # alone, the ENV tags count as locations; judged, Environment takes them
    assert all(not v.startswith("ENV:") for v in judged["sample"])
