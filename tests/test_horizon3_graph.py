"""NodeZero paths as attack maps: short labels from NodeZero's sentences, shared steps merged, always left to right."""
from __future__ import annotations


def _steps(*items):
    return [{"kind": k, "text": t, "at": "2026-03-04T13:31:59"} for k, t in items]


A = _steps(("NodeZero", "NodeZero was launched from host 10.0.0.5 on Mar 04 at 13:31:59 UTC"),
           ("Address", "NodeZero module host_discovery discovered host 10.0.0.9"),
           ("Service", "NodeZero module tcp_port_scan discovered the Printer service at 10.0.0.9:631"),
           ("Weakness", "NodeZero module lexmark_fax_rce discovered weakness CVE-2023-26068: Lexmark Printer Command Injection "
                        "Vulnerability affecting Lexmark Printer application at 10.0.0.9:631"),
           ("Impact", "Lexmark Printer Command Injection Vulnerability (CVE-2023-26068) affecting Printer service at 10.0.0.9:631"))
B = _steps(("NodeZero", "NodeZero was launched from host 10.0.0.5 on Mar 04 at 13:31:59 UTC"),
           ("Credential", "NodeZero module ntlm discovered credential for svc-backup"),
           ("Address", "NodeZero module host_discovery discovered host 10.0.0.9"),
           ("Impact", "Domain compromise"))


def test_labels_are_short_and_the_sentence_stays_in_the_details():
    from api.integrations.horizon3_graph import graphs, short
    assert [short(s["text"]) for s in A] == ["Launched from 10.0.0.5", "10.0.0.9", "Printer at 10.0.0.9:631", "CVE-2023-26068",
                                             "CVE-2023-26068 on Printer service at 10.0.0.9:631"]
    g = graphs([{"impact": "Host Compromise", "steps": A}])["all"]
    weak = next(n for n in g["nodes"] if n["kind"] == "weakness")
    assert ["What", A[3]["text"]] in weak["facts"]


def test_paths_merge_shared_steps_and_every_edge_points_right():
    from api.integrations.horizon3_graph import graphs
    out = graphs([{"impact": "Host Compromise", "steps": A}, {"impact": "Domain", "steps": B}, {"impact": "x", "steps": []}])
    g = out["all"]
    launches = [n for n in g["nodes"] if n["kind"] == "launch"]
    hosts = [n for n in g["nodes"] if n["kind"] == "host"]
    assert len(launches) == 1 and len(hosts) == 1                    # the same launch host and target appear once
    pos = {n["id"]: n["x"] for n in g["nodes"]}
    assert all(pos[e["to"]] > pos[e["from"]] for e in g["edges"])    # B reaches the host one step later: pushed right
    assert len(out["each"]) == 3 and out["each"][2] is None
    assert graphs([{"steps": []}]) is None
