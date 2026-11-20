"""CTEM's handle on the shipper's CrowdStrike alert parser (api/collector/agent/collector_cs_alert.py).

The agent folder isn't a package (its files run standalone on the shipper box), so load that one
standard-library module by path. Both sides then keep exactly the same fields.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "collector" / "agent" / "collector_cs_alert.py"
_spec = importlib.util.spec_from_file_location("ctem_cs_alert", _PATH)
csa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(csa)
