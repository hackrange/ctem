"""AI agents running on endpoints, from Tanium's Running Processes sensor: local model servers, coding and desktop
agents, MCP servers. Off unless the Tanium integration's "Pull running processes" is checked (it needs read access to
that sensor in Tanium). Only processes named like an AI agent are kept, never the rest of what people run.

A separate pass after the endpoints: if Tanium refuses the sensor, the sync still succeeds with a warning on the card.
Each endpoint's device keeps its AI processes (device.tanium["ai_processes"]); the AI Inventory reads the summary
kept in app_settings (KEY): each process, how many endpoints run it and which (up to MAX_DEVICES)."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.tanium")

SENSOR = "Running Processes"
KEY = "tanium.ai_processes"
MAX_DEVICES = 50
_PAGE = 200
# Process names (without .exe / .app) that are AI agents or model runners
AI_PROCESS = re.compile(
    r"^(ollama( app)?|lm ?studio|lms|llama(-server|-cli|file|\.cpp)?|vllm|localai|local-ai|gpt4all|jan|koboldcpp|"
    r"text-generation-webui|open-webui|claude( code)?|codex|aider|gemini(-cli)?|goose|cursor|windsurf|"
    r"copilot(-language-server|-agent)?|github copilot.*|chatgpt|openai.*|anthropic.*|perplexity|tabnine.*|codeium.*|"
    r"mcp(-server.*)?|.*-mcp(-server)?|mcp-.*)$", re.I)


def on(config: dict | None) -> bool:
    """Off by default: only when the integration's checkbox says so."""
    return (config or {}).get("pull_processes") is True


def ai_names(values: list) -> list[str]:
    """The AI agent processes among a running-process list (names only, trimmed, de-duplicated)."""
    out = {}
    for v in values or []:
        name = re.sub(r"\.(exe|app)$", "", str(v or "").strip().rsplit("\\", 1)[-1].rsplit("/", 1)[-1], flags=re.I)[:120]
        if name and AI_PROCESS.match(name):
            out.setdefault(name.lower(), name)
    return sorted(out.values(), key=str.lower)


async def sync(gw, db: AsyncSession, warnings: list[str]) -> int:
    """Read the sensor for every endpoint; keep the AI processes per device and the summary. Returns how many
    endpoints run one."""
    from api.core.device_match import find_devices
    from api.integrations.tanium_gql import sensor_args
    from api.models.device import Device
    fields = f"name sensorReadings(sensors: {sensor_args([SENSOR])}) {{ columns {{ name values }} }}"
    summary: dict[str, dict] = {}
    running = 0
    try:
        async for page in gw.pages("endpoints", fields, _PAGE):
            seen = {}
            for node in page:
                vals = [v for c in ((node.get("sensorReadings") or {}).get("columns") or []) for v in c.get("values") or []]
                if node.get("name"):
                    seen[str(node["name"])[:253]] = ai_names(vals)
            hit = await find_devices(db, list(seen))
            for name, procs in seen.items():
                dev = hit.get(name)
                if dev is None:
                    continue
                if procs or (dev.tanium or {}).get("ai_processes"):
                    dev.tanium = {**(dev.tanium or {}), "ai_processes": procs}
                if procs:
                    running += 1
                for p in procs:
                    s = summary.setdefault(p.lower(), {"name": p, "hosts": 0, "devices": []})
                    s["hosts"] += 1
                    if len(s["devices"]) < MAX_DEVICES:
                        s["devices"].append({"id": str(dev.id), "hostname": dev.hostname})
            await db.commit()
    except Exception as e:  # noqa: BLE001 -- the rest of the sync stands; the card says why
        await db.rollback()
        log.warning("Tanium running processes not read: %s", type(e).__name__)
        warnings.append(f"Tanium didn't return {SENSOR} ({type(e).__name__}); ask your Tanium administrator for read "
                        "access to that sensor, or turn off Pull running processes")
        return 0
    from api.models.settings import AppSetting
    value = json.dumps({"at": datetime.now(timezone.utc).isoformat(), "processes": sorted(summary.values(), key=lambda s: -s["hosts"])})
    row = (await db.execute(select(AppSetting).where(AppSetting.key == KEY))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=KEY, value=value))
    else:
        row.value = value
    await db.commit()
    return running


async def summary(db: AsyncSession) -> dict | None:
    from api.models.settings import AppSetting
    raw = (await db.execute(select(AppSetting.value).where(AppSetting.key == KEY))).scalar_one_or_none()
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None
