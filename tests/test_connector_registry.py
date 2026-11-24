"""Every connector module registers itself when imported; one left out of api/integrations/__init__.py fails every
sync with "No connector registered" (Grip and nine others did)."""
from __future__ import annotations

import re
from pathlib import Path


def test_every_connector_module_is_imported_and_registered():
    import api.integrations  # noqa: F401 -- what the app and the worker import
    from api.integrations.base import _REGISTRY
    folder = Path(__file__).resolve().parents[1] / "api" / "integrations"
    modules = [p.stem for p in folder.glob("*.py") if re.search(r"^@register\(", p.read_text(), re.M)]
    init = (folder / "__init__.py").read_text()
    assert [m for m in modules if not re.search(rf"^\s+{m},$", init, re.M)] == []
    for slug in ("grip", "sentinelone", "msdefender", "cortex_xdr", "fortinet", "paloalto_ngfw", "tanium", "snyk"):
        assert slug in _REGISTRY, slug
