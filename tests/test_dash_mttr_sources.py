"""Dashboard widgets: several sources at once, and Mean days to remediate as a single number."""
from __future__ import annotations

from api.core import vuln_dashboard as vd
from api.dashboards import catalog as cat
from api.dashboards import m_vulns  # noqa: F401  -- registers the metrics


def test_sources_are_a_list_and_old_single_values_still_work():
    p = cat.REGISTRY["vuln.mttr"].params
    src = next(x for x in p if x.key == "source")
    assert src.clean(["snyk", "evil", "snyk", "tenable"]) == ["snyk", "tenable"]   # allow-listed, no repeats
    assert src.clean("snyk") == ["snyk"] and src.clean("any") == [] and src.clean(None) == []
    assert src.spec()["type"] == "multi" and all(c["value"] != "any" for c in src.spec()["choices"])


def test_several_sources_filter_with_in():
    w = vd._where(["snyk", "tenable", "nope"], None)
    assert len(w) == 2 and " IN " in str(w[-1].compile(compile_kwargs={"literal_binds": True}))
    assert len(vd._where(["nope"], None)) == 1


def test_mttr_can_show_as_a_number():
    m = cat.REGISTRY["vuln.mttr"]
    assert "kpi" in m.vizzes() and m.shape_for("kpi") == "value" and m.shape_for("line") == "series"
    w = cat.clean_widget({"metric": "vuln.mttr", "viz": "kpi", "params": {"source": ["snyk"], "days": "30"},
                          "style": {"warn_at": 30, "bad_at": 60}})
    assert w["viz"] == "kpi" and w["params"]["source"] == ["snyk"] and w["style"]["bad_at"] == 60 and w["w"] == 3
    assert cat.clean_widget({"metric": "vuln.trend", "viz": "kpi"})["viz"] != "kpi"   # only where a number is offered


def test_vulnerabilities_by_quarter_is_offered_with_filters():
    from api.dashboards import m_vuln_quarter  # noqa: F401
    m = cat.REGISTRY["vuln.quarter"]
    keys = [p.key for p in m.params]
    assert m.category == "Vulnerabilities" and m.shape == "value" and m.filterable
    assert keys[:2] == ["quarter", "measure"] and "source" in keys and "device_type" in keys
    w = cat.clean_widget({"metric": "vuln.quarter", "params": {"quarter": "q2", "measure": "mttr", "source": ["snyk"]}})
    assert w["params"]["quarter"] == "q2" and w["params"]["measure"] == "mttr" and w["viz"] == "kpi"
    assert cat.clean_widget({"metric": "vuln.quarter", "params": {"measure": "drop table"}})["params"]["measure"] == "open"
