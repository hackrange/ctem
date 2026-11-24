"""The Identity page's scripts: a local variable must not hide a helper the same function calls (a "sev" filter value
hid the sev() badge helper, so every ITDR threat list failed with "Error loading threats")."""
from __future__ import annotations

import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "api/web/templates/pages/identity.html"


def test_no_function_hides_a_helper_it_calls():
    src = PAGE.read_text()
    helpers = set(re.findall(r"^function (\w+)\(", src, re.M))
    bodies = re.split(r"^(?:async )?function \w+\([^)]*\) \{", src, flags=re.M)[1:]
    for body in bodies:
        body = body.split("\n}\n", 1)[0]
        for name in set(re.findall(r"\b(?:const|let|var) (\w+)\s*=", body)) & helpers:
            assert not re.search(rf"\b{name}\(", body), f"a local {name!r} hides the {name}() helper it calls"


def test_every_summary_card_opens_its_tab():
    src = PAGE.read_text()
    cards = re.findall(r'<(\w+) type="button" class="stat-tile loading" id="tile-[\w-]+" data-open="(\w+)"', src)
    assert len(cards) == 6 and {tag for tag, _ in cards} == {"button"}
    tabs = set(re.findall(r'id="tab-btn-(\w+)"', src))
    assert {t for _, t in cards} - tabs == {"unsanctioned"}        # the one card without its own tab filters the apps tab
    assert "sanctioned=false" in src
