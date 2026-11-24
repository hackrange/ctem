"""Threat Hunt findings: an attack map per finding, and a PDF report that keeps everything on the page."""
from __future__ import annotations

import json

import pytest

ISSUE = {
    "title": "Likely malware on DESKTOP001 contacting an outside server", "severity": "critical", "confidence": "high",
    "what_happened": "Several alerts on DESKTOP001 back each other up.", "why_it_matters": "It may be under remote control.",
    "timeline": [{"time": "2026-11-10 18:00", "source": "crowdstrike", "what": "MSBuild ran a suspicious file on DESKTOP001.", "lookup": 1},
                 {"time": "2026-11-10 18:05", "source": "crowdstrike", "what": "jdoe ran PowerShell that downloaded a file.", "lookup": 1},
                 {"time": "2026-11-10 18:07", "source": "splunk", "what": "Traffic to 203.0.113.7 looked like C2.", "lookup": 2},
                 {"time": "unknown", "source": "crowdstrike", "what": "Process hollowing detected.", "lookup": 1},
                 {"time": "unknown", "source": "crowdstrike", "what": "Obfuscated data sent out.", "lookup": 1}],
    "involved": {"hosts": ["DESKTOP001"], "users": ["jdoe"], "ips": ["203.0.113.7"]},
    "attack": [{"id": "T1055", "name": "Process Injection", "plain": "Hides inside a normal program.", "url": "https://attack.mitre.org/techniques/T1055/"}],
    "what_to_do": ["Isolate DESKTOP001.", "Reset jdoe's password."], "lookups": [1, 2], "window_label": "Nov 10 17:30 to 18:30 UTC",
}
WIDE = {"title": "All tool alerts", "source_label": "open-ctem", "count": 50, "columns": [f"col{i}" for i in range(14)],
        "rows": [{f"col{i}": ("x" * 300 if i == 3 else f"v{i}") for i in range(14)} for _ in range(8)]}
RESULT = {"issues": [ISSUE], "lookups": [WIDE, {"title": "Splunk", "source_label": "Splunk", "count": 1, "spl": "search index=net " + "a" * 900,
                                                  "columns": ["dest"], "rows": [{"dest": "203.0.113.7"}]}], "sources": ["open-ctem", "splunk"]}


def test_a_finding_maps_people_computers_then_each_step_in_order():
    from api.hunt.graph import PER_COL, build
    g = build(ISSUE)
    kinds = {n["id"]: n["kind"] for n in g["nodes"]}
    assert kinds["u0"] == "user" and kinds["a0"] == "ip" and kinds["h0"] == "host"
    edges = {(e["from"], e["to"], e["label"]) for e in g["edges"]}
    assert ("h0", "s0", "on") in edges and ("u0", "s1", "by") in edges and ("a0", "s2", "involved") in edges
    assert all(("s%d" % (i - 1), "s%d" % i, "then") in edges for i in range(1, 5))
    s = {n["id"]: n for n in g["nodes"]}
    assert s["s0"]["x"] == s["s1"]["x"] and s[f"s{PER_COL}"]["x"] > s["s0"]["x"]     # four to a column, then the next
    assert s["s4"]["hit"] and [x["n"] for x in g["steps"]] == [1, 2, 3, 4, 5] and g["w"] > 0 and g["h"] > 0


def test_the_pdf_has_the_logo_story_map_and_nothing_wider_than_the_page():
    import base64
    import io

    from PIL import Image

    from api.hunt import report_pdf
    from api.hunt.graph import build
    buf = io.BytesIO()
    Image.new("RGBA", (300, 80), (255, 255, 255, 255)).save(buf, "PNG")
    logo = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    seen = []
    real = report_pdf.Table.wrap

    def wrap(self, aw, ah):   # every table must fit the page width it is given
        w, h = real(self, aw, ah)
        seen.append((w, aw))
        return w, h
    report_pdf.Table.wrap = wrap
    try:
        pdf = report_pdf.build(ISSUE, RESULT, {"report_id": "ABC-1", "generated": "2026-11-24 19:00 UTC", "prepared_by": "analyst",
                                               "app_title": "open-ctem", "org_name": "Acme <b>", "accent_color": "#f5a623",
                                               "logo_url": logo, "light_logo_url": None, "graph": build(ISSUE)})
    finally:
        report_pdf.Table.wrap = real
    assert pdf.startswith(b"%PDF") and len(pdf) > 5000 and b"/XObject" in pdf   # the logo is in
    assert seen and [x for x in seen if x[0] > x[1] + 0.5] == []
    assert report_pdf._logo("data:image/png;base64,bm90IGFuIGltYWdl") is None and report_pdf._logo("/static/x.png") is None


@pytest.mark.asyncio
async def test_the_report_and_map_endpoints_are_for_cyber_and_admin(db, client_cyber, client_read_only):
    from api.hunt.watch import WATCH_KEY
    from api.models.settings import AppSetting
    from sqlalchemy import select
    row = (await db.execute(select(AppSetting).where(AppSetting.key == WATCH_KEY))).scalar_one_or_none()
    row = row or AppSetting(key=WATCH_KEY, is_sensitive=False)
    row.value = json.dumps({"ran_at": "2026-11-24T19:00:00+00:00", "result": RESULT})
    db.add(row)
    await db.commit()
    assert (await client_read_only.get("/api/v1/hunt/report/watch/0/pdf")).status_code == 403
    r = await client_cyber.get("/api/v1/hunt/report/watch/0/pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF")
    assert 'attachment; filename="incident-report-WATCH-1.pdf"' == r.headers["content-disposition"]
    g = (await client_cyber.get("/api/v1/hunt/graph/watch/0")).json()
    assert g["nodes"] and g["steps"]
    assert (await client_cyber.get("/api/v1/hunt/graph/watch/7")).status_code == 404
    assert (await client_cyber.get("/api/v1/hunt/graph/someone-elses-task/0")).status_code == 404
