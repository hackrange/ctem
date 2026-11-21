"""The widget catalog: every metric a dashboard can show, its allowed options, and who may see it.

A widget stored on a dashboard is {metric, viz, title, params, x, y, w, h}. Nothing in it is a query: the metric
is an id from this catalog, params are checked against the metric's allow-listed options, and the numbers are
computed for whoever is looking, limited to the devices and data that person may see.

Shapes a metric returns:
  value   {"value": n, "unit": "%"|None, "href": str|None, "note": str|None, "max"?: n (for a gauge),
           "delta"?: {"pct", "was", "better": "up"|"down"}, "spark"?: [n...]}
  series  {"x": [...], "series": [{"name", "data", "stack"?, "color"?, "type"?: "line", "axis"?: 1}], "y_unit"?, "y2_unit"?}
  parts   {"items": [{"name", "value", "href"?, "color"?}], "center"?: {"value", "label"}}
  table   {"columns": [...], "rows": [[...]], "hrefs": [str|None]}
  points  {"x_label", "y_label", "size_label"?, "groups": [{"name", "color"?, "points": [[x, y, size, label, href]]}]}
Any shape may add "headline" (a one-line takeaway shown above the chart) and "note".
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.dashboards")

VIZ_FOR = {"value": ("kpi", "gauge"), "series": ("line", "area", "bar", "stacked"), "parts": ("donut", "pie", "bar", "column", "table"),
           "table": ("table",), "points": ("bubble", "scatter")}
# Colors a widget may use, by name (the renderer maps them; nothing else is accepted)
COLORS = {"blue": "#3b82f6", "green": "#22c55e", "red": "#ef4444", "orange": "#f97316", "yellow": "#eab308",
          "purple": "#a855f7", "teal": "#14b8a6", "gray": "#64748b"}
# Dashboard themes: a palette for non-severity colors and a card style. Severity colors never change meaning.
THEMES = ("default", "ocean", "sunset", "forest", "violet", "slate", "neon")
GRID_COLS = 12
MAX_WIDGETS = 40
CACHE_SECONDS = 900


@dataclass(frozen=True)
class Param:
    key: str
    label: str
    choices: tuple | None = None      # allowed values (first is the default) ...
    low: int | None = None            # ... or an int range
    high: int | None = None
    default: Any = None
    labels: dict = field(default_factory=dict)

    def clean(self, value):
        if self.choices is not None:
            v = value if value in self.choices else (self.default if self.default is not None else self.choices[0])
            return v
        if self.low is not None:
            try:
                v = int(value)
            except (TypeError, ValueError):
                return self.default
            return min(max(v, self.low), self.high)
        return bool(value) if value is not None else bool(self.default)

    def spec(self) -> dict:
        out = {"key": self.key, "label": self.label, "default": self.default if self.default is not None
               else (self.choices[0] if self.choices else None)}
        if self.choices is not None:
            out["choices"] = [{"value": c, "label": self.labels.get(c, str(c).replace("_", " "))} for c in self.choices]
        elif self.low is not None:
            out.update(type="int", min=self.low, max=self.high)
        else:
            out["type"] = "bool"
        return out


@dataclass
class Ctx:
    """Who is looking: their device scope (None = every device) and what else they may see."""
    db: AsyncSession
    user: Any
    scope: Any
    grc: bool
    threats: bool
    decider: bool
    filtered: bool = False            # a widget filter narrowed the devices (snapshot trends can't follow it)

    @property
    def viewer_key(self) -> str:
        return "all" if self.scope is None else f"u{self.user.id}"


@dataclass(frozen=True)
class Metric:
    id: str
    label: str
    category: str
    shape: str
    params: tuple[Param, ...]
    run: Callable[[Ctx, dict], Awaitable[dict]]
    description: str = ""
    needs: str | None = None          # "grc" | "threats": hidden from people who can't see that data
    per_user: bool = False            # result depends on the person even for fleet-wide roles (e.g. own requests)
    filterable: bool = True           # counts devices, so widget filters (tags, sources...) apply

    def spec(self) -> dict:
        return {"id": self.id, "label": self.label, "category": self.category, "shape": self.shape,
                "viz": list(VIZ_FOR[self.shape]), "description": self.description, "filterable": self.filterable,
                "params": [p.spec() for p in self.params]}


REGISTRY: dict[str, Metric] = {}


def metric(m: Metric) -> Metric:
    REGISTRY[m.id] = m
    return m


def allowed(m: Metric, ctx: Ctx) -> bool:
    return m.needs is None or (m.needs == "grc" and ctx.grc) or (m.needs == "threats" and ctx.threats)


async def context(db: AsyncSession, user) -> Ctx:
    from api.auth.device_scope import device_scope
    from api.auth.rbac import _load_user_permissions
    from api.core import tag_roles
    await tag_roles.ensure(db)   # filters and the AI read this install's tag mapping
    perms = await _load_user_permissions(user, db)
    roles = set(user.role_names)
    return Ctx(db=db, user=user, scope=await device_scope(user, db),
               grc=any(p.startswith("grc:read:") for p in perms) or "admin" in roles,
               threats=bool({"admin", "cyber"} & roles), decider=bool({"admin", "cyber"} & roles))


def clean_widget(w) -> dict | None:
    """A stored widget, reduced to known fields and allowed values. None if its metric doesn't exist."""
    if not isinstance(w, dict) or w.get("metric") not in REGISTRY:
        return None
    m = REGISTRY[w["metric"]]
    viz = w.get("viz") if w.get("viz") in VIZ_FOR[m.shape] else VIZ_FOR[m.shape][0]
    raw = w.get("params") if isinstance(w.get("params"), dict) else {}
    params = {p.key: p.clean(raw.get(p.key)) for p in m.params}
    title = " ".join(str(w.get("title") or m.label).split())[:120] or m.label
    title = "".join(ch for ch in title if ch not in "<>")

    def num(k, lo, hi, d):
        try:
            return min(max(int(w.get(k)), lo), hi)
        except (TypeError, ValueError):
            return d
    wid = str(w.get("id") or "")
    wid = wid if wid.replace("-", "").isalnum() and len(wid) <= 40 else ""
    from api.dashboards import filters as flt
    conds = flt.clean(w.get("filters")) if m.filterable else []
    return {"id": wid, "metric": m.id, "viz": viz, "title": title, "params": params, "style": clean_style(w.get("style"), m.shape),
            "filters": conds, "filter_match": "any" if conds and w.get("filter_match") == "any" else "all",
            "x": num("x", 0, GRID_COLS - 1, 0), "y": num("y", 0, 500, 0),
            "w": num("w", 1, GRID_COLS, 4 if m.shape != "value" else 3), "h": num("h", 1, 12, 4 if m.shape != "value" else 2)}


def clean_style(s, shape: str) -> dict:
    """How a widget looks: a color from COLORS, and for single numbers the amber and red thresholds (and whether
    higher is worse). Anything else is dropped."""
    s = s if isinstance(s, dict) else {}
    out = {}
    if s.get("color") in COLORS:
        out["color"] = s["color"]
    try:   # fill transparency: 100 is solid
        op = int(s.get("opacity"))
        if 20 <= op < 100:
            out["opacity"] = op
    except (TypeError, ValueError):
        pass
    if shape == "value":
        for k in ("warn_at", "bad_at"):
            try:
                v = float(s.get(k))
                if -1e12 < v < 1e12:
                    out[k] = int(v) if v.is_integer() else round(v, 2)
            except (TypeError, ValueError):
                pass
        if out.get("warn_at") is not None or out.get("bad_at") is not None:
            out["higher_is_worse"] = s.get("higher_is_worse") is not False
    return out


async def evaluate(ctx: Ctx, widget: dict) -> dict:
    """One widget's data for this viewer, cached briefly per metric, options and viewer scope."""
    m = REGISTRY.get(widget.get("metric"))
    if m is None:
        return {"error": "This widget's metric no longer exists."}
    if not allowed(m, ctx):
        return {"error": "You don't have access to this data."}
    params = {p.key: p.clean((widget.get("params") or {}).get(p.key)) for p in m.params}
    viewer = f"u{ctx.user.id}" if m.per_user else ctx.viewer_key
    from api.dashboards import filters as flt
    conds = flt.clean(widget.get("filters")) if m.filterable else []
    match = "any" if widget.get("filter_match") == "any" else "all"
    if conds:   # narrow the devices like a scope does; every device-based metric already honors the scope
        import dataclasses
        import hashlib

        from sqlalchemy import and_

        from api.core import tag_roles
        await tag_roles.ensure(ctx.db)
        cond = await flt.where(ctx.db, conds, match, ctx.user)
        if flt.personal(conds):
            viewer = f"u{ctx.user.id}"
        ctx = dataclasses.replace(ctx, scope=cond if ctx.scope is None else and_(ctx.scope, cond), filtered=True)
        viewer += ":f" + hashlib.sha256(json.dumps([conds, match], sort_keys=True).encode()).hexdigest()[:16]
    key = "dashw:v1:" + m.id + ":" + json.dumps(params, sort_keys=True) + ":" + viewer
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    r = aioredis.from_url(get_settings().redis_url)
    try:
        try:
            hit = await r.get(key)
            if hit:
                return json.loads(hit)
        except Exception:  # noqa: BLE001 -- no cache, still an answer
            log.warning("widget cache unavailable")
        try:
            out = {"shape": m.shape, **await m.run(ctx, params)}
            if conds and isinstance(out.get("href"), str) and out["href"].startswith("/devices"):
                from urllib.parse import urlencode
                extra = flt.link_params(conds, match)
                if extra:
                    out["href"] += ("&" if "?" in out["href"] else "?") + urlencode(extra, doseq=True)
        except Exception:  # noqa: BLE001 -- one broken widget must not break the dashboard
            log.exception("widget %s failed", m.id)
            return {"error": "This widget couldn't be loaded just now."}
        try:
            await r.set(key, json.dumps(out, default=str), ex=CACHE_SECONDS)
        except Exception:  # noqa: BLE001
            log.warning("widget result not cached")
        return out
    finally:
        await r.aclose()


def load_metrics() -> None:
    """Importing the metric modules is what registers them."""
    from api.dashboards import m_assets, m_devices, m_directory, m_other, m_risk, m_vulns  # noqa: F401
