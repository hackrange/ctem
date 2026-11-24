"""Attack maps (an alert's, a hunt finding's): one layout for the page (attack_map.js draws it and makes it
interactive) and the PDF report (drawn here with ReportLab). A graph is {"nodes": [...], "edges": [...]}: each node
has an id, kind, label, optional sub, col (left to right in the order things happened), optional row, hit and facts;
each edge has from, to, label and hot (on the path that matters)."""
from __future__ import annotations

COLW, ROWH, R, TOP, LEFT = 230, 88, 20, 60, 90
COLOR = {"host": "#3a8ee8", "user": "#e8913a", "process": "#4a5568", "detection": "#e05252", "action": "#3aa76d",
         "quarantine": "#e05252", "indicator": "#9b59b6", "file": "#e8913a", "network": "#e8913a", "dns": "#e8913a",
         "event": "#4a5568", "alert": "#e05252", "log": "#3a8ee8", "ip": "#e8913a", "launch": "#4a5568", "service": "#e8913a",
         "weakness": "#e05252", "credential": "#9b59b6", "impact": "#c62828"}
LETTER = {"host": "H", "user": "U", "process": "P", "detection": "!", "action": "E", "quarantine": "Q", "indicator": "I",
          "file": "F", "network": "N", "dns": "D", "event": "S", "alert": "!", "log": "L", "ip": "N", "launch": "P", "service": "S",
          "weakness": "W", "credential": "K", "impact": "!"}
HOT, COOL = "#e05252", "#e8913a"


def layout(g: dict) -> dict:
    """Give each node x and y, and the graph its width and height. Nodes in a column are centred on the tallest
    column, unless they carry their own row (a grid, as hunt findings use)."""
    rowh = g.get("rowh", ROWH)
    cols = sorted({n["col"] for n in g["nodes"]})
    per = {c: [n for n in g["nodes"] if n["col"] == c] for c in cols}
    rows = max((n["row"] + 1 for n in g["nodes"] if "row" in n), default=0)
    most = max([len(v) for v in per.values()] + [rows, 1])
    for ci, c in enumerate(cols):
        for i, n in enumerate(per[c]):
            row = n.get("row", i)
            shift = 0 if "row" in n else (most - len(per[c])) * rowh / 2
            n["x"], n["y"] = LEFT + ci * COLW, TOP + shift + row * rowh
    g["w"] = LEFT + max(len(cols) - 1, 0) * COLW + 200
    g["h"] = max(most * rowh + TOP, 320)
    return g


def edge_path(a: dict, b: dict) -> tuple[tuple, tuple, tuple, tuple]:
    """Start, two control points and end of an edge: left to right between columns, or straight down within one
    (below the first box's label)."""
    if abs(b["x"] - a["x"]) < 1:
        y1, y2 = a["y"] + R + 36, b["y"] - R - 6
        return (a["x"], y1), (a["x"], (y1 + y2) / 2), (b["x"], (y1 + y2) / 2), (b["x"], y2)
    x1, x2 = a["x"] + R, b["x"] - R - 6
    mx = (x1 + x2) / 2
    return (x1, a["y"]), (mx, a["y"]), (mx, b["y"]), (x2, b["y"])


def _short(s, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 3] + "..."


def drawing(g: dict, width: float, font: str = "Helvetica", bold: str = "Helvetica-Bold"):
    """The map as a ReportLab drawing that fits `width` points (never wider than the page), for the PDF."""
    from reportlab.graphics.shapes import Circle, Drawing, Group, Path, Polygon, Rect, String
    from reportlab.lib.colors import HexColor, white
    w, h = g["w"] + 40, g["h"]
    scale = min(1.0, width / w)
    d = Drawing(w * scale, h * scale)
    grp = Group()
    grp.transform = (scale, 0, 0, -scale, 20 * scale, h * scale)   # SVG-style y down, like the page
    pos = {n["id"]: n for n in g["nodes"]}
    for e in g["edges"]:
        a, b = pos.get(e["from"]), pos.get(e["to"])
        if not a or not b:
            continue
        c = HexColor(HOT if e.get("hot") else COOL)
        p0, c1, c2, p3 = edge_path(a, b)
        p = Path(strokeColor=c, strokeWidth=2.4 if e.get("hot") else 1.3, fillColor=None)
        p.moveTo(*p0)
        p.curveTo(*c1, *c2, *p3)
        grp.add(p)
        x2, y2 = p3
        if p0[0] == p3[0]:   # pointing down
            grp.add(Polygon([x2, y2 + 6, x2 - 4, y2 - 2, x2 + 4, y2 - 2], fillColor=c, strokeColor=c))
        else:
            grp.add(Polygon([x2 + 6, y2, x2 - 2, y2 - 4, x2 - 2, y2 + 4], fillColor=c, strokeColor=c))
        label = _short(e.get("label"), 18)
        lw = len(label) * 5.6 + 14
        mx, my = (p0[0] + p3[0]) / 2, (p0[1] + p3[1]) / 2
        grp.add(Rect(mx - lw / 2, my - 8, lw, 16, rx=8, ry=8, fillColor=white, strokeColor=c, strokeWidth=0.8))
        grp.add(_flip(String(mx, my, label, fontName=font, fontSize=9, textAnchor="middle"), my, 3))
    for n in g["nodes"]:
        x, y = n["x"], n["y"]
        grp.add(Circle(x, y, R, fillColor=HexColor(COLOR.get(n["kind"], "#7f8c8d")),
                       strokeColor=HexColor(HOT) if n.get("hit") else white, strokeWidth=3 if n.get("hit") else 2))
        grp.add(_flip(String(x, y, LETTER.get(n["kind"], "*"), fontName=bold, fontSize=12, fillColor=white, textAnchor="middle"), y, 4))
        grp.add(_flip(String(x, y + R + 14, _short(n["label"], 30), fontName=font, fontSize=10, textAnchor="middle"), y + R + 14, 0))
        if n.get("sub"):
            grp.add(_flip(String(x, y + R + 27, _short(n["sub"], 34), fontName=font, fontSize=8.5, fillColor=HexColor("#5f6b7a"),
                                 textAnchor="middle"), y + R + 27, 0))
    d.add(grp)
    return d


def _flip(s, y: float, nudge: float):
    """Text drawn in the y-down group would be upside down: flip it back around its own baseline."""
    from reportlab.graphics.shapes import Group
    s.y = 0
    t = Group(s)
    t.transform = (1, 0, 0, -1, 0, y + nudge)
    return t
