"""A Threat Hunt finding as a PDF incident report: the organization's logo, the story told in order (not wide tables),
the attack map drawn in, and evidence as wrapped cards, so nothing runs off the page. ReportLab only: nothing is
fetched (the logo is the stored branding image), and every piece of text is escaped before it becomes markup."""
from __future__ import annotations

import base64
import html
import io
import os
from collections import Counter

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from api.core.attack_map import drawing

PAGE_W, PAGE_H = letter
MARGIN = 0.65 * inch
FRAME_W = PAGE_W - 2 * MARGIN - 12   # the frame keeps 6 points of padding on each side
BAND_H = 1.05 * inch
INK, MUTED, LINE, SOFT = colors.HexColor("#1d2330"), colors.HexColor("#5f6b7a"), colors.HexColor("#e3e7ee"), colors.HexColor("#f6f8fb")
SEV = {"critical": "#c62828", "high": "#e8711a", "medium": "#d6a100", "low": "#2e7d32"}
ROWS_SHOWN, CELL_MAX = 5, 500
_DEJAVU = "/usr/share/fonts/truetype/dejavu/"


def _fonts() -> tuple[str, str, str, bool]:
    """DejaVu when the image has it (any character prints), else the built-in fonts (Latin-1 only)."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    try:
        for name, f in (("Dv", "DejaVuSans.ttf"), ("DvB", "DejaVuSans-Bold.ttf"), ("DvM", "DejaVuSansMono.ttf")):
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, os.path.join(_DEJAVU, f)))
        return "Dv", "DvB", "DvM", True
    except Exception:  # noqa: BLE001 -- no font files: the built-in fonts still make a readable report
        return "Helvetica", "Helvetica-Bold", "Courier", False


class _Report:
    def __init__(self, unicode_ok: bool, fonts: tuple[str, str, str]):
        self.uni = unicode_ok
        self.font, self.bold, self.mono = fonts
        base = dict(fontName=self.font, textColor=INK, alignment=TA_LEFT)
        st = lambda name, **kw: ParagraphStyle(name, **{**base, **kw})   # noqa: E731
        self.s = {
            "title": st("title", fontName=self.bold, fontSize=19, leading=24, spaceAfter=6),
            "meta": st("meta", fontSize=9, leading=13, textColor=MUTED),
            "h2": st("h2", fontName=self.bold, fontSize=10, leading=13, textColor=MUTED, spaceBefore=16, spaceAfter=6),
            "body": st("body", fontSize=10, leading=15),
            "small": st("small", fontSize=8.5, leading=11.5, textColor=MUTED),
            "cell": st("cell", fontSize=8.5, leading=11, wordWrap="CJK"),
            "mono": st("mono", fontName=self.mono, fontSize=7.8, leading=10, wordWrap="CJK"),
            "kpi": st("kpi", fontName=self.bold, fontSize=15, leading=18),
        }

    def plain(self, v) -> str:
        """Text in characters the fonts can print (canvas text, not markup)."""
        s = str(v if v is not None else "")
        return s if self.uni else s.encode("latin-1", "replace").decode("latin-1")

    def t(self, v, cap: int = 4000) -> str:
        """Text as safe Paragraph markup, cut to `cap`."""
        return html.escape(self.plain(" ".join(str(v if v is not None else "").split())[:cap]), quote=False)

    def p(self, v, style="body", cap=4000) -> Paragraph:
        return Paragraph(self.t(v, cap), self.s[style])


def _logo(data_url: str | None):
    """The stored branding logo (a checked data: image) as something ReportLab can draw, or None."""
    from reportlab.lib.utils import ImageReader

    from api.core.branding_image import real_image
    if not data_url or not data_url.startswith("data:") or not real_image(data_url):
        return None
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(base64.b64decode(data_url.split(",", 1)[1])))
        img.load()
        out = io.BytesIO()
        img.convert("RGBA").save(out, "PNG")
        out.seek(0)
        return ImageReader(out), img.width / max(img.height, 1)
    except Exception:  # noqa: BLE001 -- a logo that won't open leaves the report without one
        return None


def _pages(logo, light_logo, label: str, accent: str, footer: str, font: str, bold: str):
    """The first page's dark band with the logo, and the later pages' slim header with the logo made for light
    backgrounds (the sign-in page's, when there is one); a footer on every page."""
    def foot(c, doc):
        c.setFont(font, 7.5)
        c.setFillColor(MUTED)
        c.drawString(MARGIN, 0.42 * inch, footer[:120])
        c.drawRightString(PAGE_W - MARGIN, 0.42 * inch, f"Page {doc.page}")

    def first(c, doc):
        c.saveState()
        c.setFillColor(colors.HexColor("#141a26"))
        c.rect(0, PAGE_H - BAND_H, PAGE_W, BAND_H, fill=1, stroke=0)
        c.setFillColor(colors.HexColor(accent))
        c.rect(0, PAGE_H - BAND_H - 4, PAGE_W, 4, fill=1, stroke=0)
        x = MARGIN
        if logo:
            w = min(0.5 * inch * logo[1], 2.6 * inch)
            c.drawImage(logo[0], x, PAGE_H - BAND_H / 2 - (w / logo[1]) / 2, width=w, height=w / logo[1], mask="auto")
            x += w + 0.25 * inch
        c.setFillColor(colors.white)
        c.setFont(bold, 9)
        c.drawString(x, PAGE_H - BAND_H / 2 - 3, label.upper()[:90])
        foot(c, doc)
        c.restoreState()

    def later(c, doc):
        c.saveState()
        c.setStrokeColor(LINE)
        c.line(MARGIN, PAGE_H - 0.5 * inch, PAGE_W - MARGIN, PAGE_H - 0.5 * inch)
        small = light_logo or logo
        if small:
            w = min(0.24 * inch * small[1], 1.4 * inch)
            c.drawImage(small[0], MARGIN, PAGE_H - 0.47 * inch, width=w, height=w / small[1], mask="auto")
        c.setFont(font, 8)
        c.setFillColor(MUTED)
        c.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.42 * inch, label[:100])
        foot(c, doc)
        c.restoreState()
    return first, later


def build(issue: dict, result: dict, meta: dict) -> bytes:
    """meta: report_id, generated, prepared_by, app_title, org_name, accent_color, logo_url (on the dark band),
    light_logo_url (the page headers), graph."""
    font, bold, mono, uni = _fonts()
    r = _Report(uni, (font, bold, mono))
    s = r.s
    accent = colors.HexColor(meta["accent_color"])
    sev = (issue.get("severity") or "medium").lower()
    sep = " &nbsp;·&nbsp; " if uni else " | "
    story = [Spacer(1, BAND_H - 0.35 * inch), r.p(issue.get("title"), "title", 300),
             Paragraph(sep.join([f'<font color="{SEV.get(sev, "#5f6b7a")}"><b>{r.t(sev.upper())}</b></font>',
                                 f'Report {r.t(meta["report_id"])}', f'Generated {r.t(meta["generated"])}',
                                 f'Prepared by {r.t(meta["prepared_by"])}', "Confidential"]), s["meta"])]
    if issue.get("window_label"):
        story.append(r.p(f"Incident window: {issue['window_label']}", "meta"))
    who = issue.get("involved") or {}
    timeline = [t for t in issue.get("timeline") or [] if isinstance(t, dict)]
    by_source = Counter(str(t.get("source") or "Other") for t in timeline).most_common()
    kpis = [("Severity", sev.capitalize()), ("Confidence", str(issue.get("confidence") or "").capitalize()),
            ("Steps seen", str(len(timeline))), ("Sources agreeing", str(len(by_source))),
            ("Assets involved", str(sum(len(who.get(k) or []) for k in ("hosts", "users", "ips"))))]
    kt = Table([[[r.p(k, "small"), r.p(v, "kpi")] for k, v in kpis]], colWidths=[FRAME_W / 5] * 5)
    kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story += [Spacer(1, 10), kt, r.p("EXECUTIVE SUMMARY", "h2")]
    box = Table([[r.p(issue.get("what_happened"))]], colWidths=[FRAME_W])
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("LINEBEFORE", (0, 0), (0, -1), 3, accent),
                             ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 8),
                             ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story.append(box)
    if issue.get("why_it_matters"):
        story += [r.p("WHY IT MATTERS", "h2"), r.p(issue["why_it_matters"])]
    g = meta.get("graph")
    if g and g.get("nodes"):
        width = FRAME_W
        if g["h"] * width / (g["w"] + 40) > 4.6 * inch:   # a tall map is made narrower so it stays on one page
            width = 4.6 * inch * (g["w"] + 40) / g["h"]
        story.append(KeepTogether([r.p("ATTACK PATH", "h2"), drawing(g, min(width, FRAME_W), font, bold),
                                   r.p("Accounts and addresses on the left, then the computers, then each step in order. "
                                       "Red marks the path of the attack.", "small")]))
    _unfolded(story, r, timeline, by_source, accent, sev)
    story += [r.p("WHO AND WHAT WAS INVOLVED", "h2")] + [
        Paragraph(f"<b>{label}:</b> {r.t(', '.join(str(x) for x in who.get(k) or []) or 'none')}", s["body"])
        for label, k in (("Computers", "hosts"), ("Accounts", "users"), ("Addresses", "ips"))]
    if issue.get("attack"):
        story.append(r.p("ATTACK TECHNIQUES (MITRE ATT&CK)", "h2"))
        att = ParagraphStyle("att", parent=s["body"], spaceAfter=4)
        story += [Paragraph(f'<b>{r.t(a.get("id"))}</b> {r.t(a.get("name"))}<br/><font color="#5f6b7a">{r.t(a.get("plain"))}</font>', att)
                  for a in issue["attack"] if isinstance(a, dict)]
    if issue.get("what_to_do"):
        story.append(r.p("RECOMMENDED ACTIONS", "h2"))
        mark = "☐" if uni else "[ ]"
        todo = ParagraphStyle("todo", parent=s["body"], leftIndent=16, firstLineIndent=-16, spaceAfter=4)
        story += [Paragraph(f"{mark}&nbsp; {r.t(x)}", todo) for x in issue["what_to_do"]]
    _appendix(story, r, issue, result)
    dot = "  ·  " if uni else " | "
    footer = r.plain(dot.join([f"{meta['app_title']} Threat Hunt", f"Report {meta['report_id']}", "Confidential"]))
    label = r.plain("Cyber security incident report" + (dot + meta["org_name"] if meta.get("org_name") else ""))
    first, later = _pages(_logo(meta.get("logo_url")), _logo(meta.get("light_logo_url")), label, meta["accent_color"], footer, font, bold)
    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=letter, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=0.7 * inch,
                            bottomMargin=0.7 * inch, title=f"Incident report {meta['report_id']}", author=r.plain(meta["app_title"]),
                            subject=r.plain(str(issue.get("title") or "")[:200]), creator="open-ctem")
    doc.build(story, onFirstPage=first, onLaterPages=later)
    return out.getvalue()


def _unfolded(story: list, r: _Report, timeline: list[dict], by_source: list, accent, sev: str) -> None:
    """The steps as a numbered story line, then how much each source saw."""
    if not timeline:
        return
    s = r.s
    story.append(r.p("HOW IT UNFOLDED", "h2"))
    num = ParagraphStyle("n", parent=s["cell"], textColor=colors.white, alignment=1)
    for n, t in enumerate(timeline, 1):
        lookup = f" &nbsp; evidence #{r.t(t['lookup'])}" if t.get("lookup") else ""
        head = Paragraph(f'<b>{r.t(t.get("time") or "Time unknown")}</b> <font color="#5f6b7a">&nbsp; {r.t(t.get("source"))}{lookup}</font>',
                         s["cell"])
        row = Table([[Paragraph(f"<b>{n}</b>", num), [head, Spacer(1, 2), r.p(t.get("what"))]]],
                    colWidths=[0.32 * inch, FRAME_W - 0.32 * inch])
        row.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), accent if n < len(timeline) else colors.HexColor(SEV.get(sev, "#c62828"))),
                                 ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (1, 0), (1, 0), 10),
                                 ("LINEBELOW", (1, 0), (1, 0), 0.5, LINE), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
        story += [KeepTogether(row), Spacer(1, 4)]
    top = max([c for _, c in by_source] or [1])
    rows = []
    for name, count in by_source:
        bar = Table([[""]], colWidths=[max(4, (FRAME_W - 2.4 * inch - 12) * count / top)], rowHeights=[9])   # inside the cell's padding
        bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), accent)]))
        rows.append([r.p(name, "cell", 60), bar, r.p(str(count), "cell")])
    bt = Table(rows, colWidths=[1.8 * inch, FRAME_W - 2.4 * inch, 0.6 * inch])
    bt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, -1), "LEFT")]))
    story.append(KeepTogether([r.p("EVIDENCE BY SOURCE", "h2"), bt]))


def _appendix(story: list, r: _Report, issue: dict, result: dict) -> None:
    """Each evidence search as a card: what it was, the search, and its first rows as wrapped field: value lines."""
    lookups = result.get("lookups") or []
    picked = [(n, lookups[n - 1]) for n in issue.get("lookups") or [] if isinstance(n, int) and 0 < n <= len(lookups)]
    if not picked:
        return
    story.append(r.p("APPENDIX: EVIDENCE", "h2"))
    for n, lk in picked:
        window = f" &nbsp; {r.t(lk['window_label'])}" if lk.get("window_label") else ""
        head = [Paragraph(f'<b>#{n} {r.t(lk.get("title"), 200)}</b> <font color="#5f6b7a">&nbsp; {r.t(lk.get("source_label"))}'
                          f' &nbsp; {r.t(lk.get("count", 0))} rows{window}</font>', r.s["body"])]
        if lk.get("spl"):
            head.append(Paragraph(r.t(lk["spl"], 2000), r.s["mono"]))
        story.append(KeepTogether(head))
        cols = [str(c) for c in lk.get("columns") or [] if c != "alert_page"]   # a link only works in CTEM
        for row in (lk.get("rows") or [])[:ROWS_SHOWN]:
            if not isinstance(row, dict):
                continue
            pairs = [[r.p(c, "small", 60), r.p(row.get(c), "cell", CELL_MAX)] for c in cols if row.get(c) not in (None, "")]
            if not pairs:
                continue
            card = Table(pairs, colWidths=[1.45 * inch, FRAME_W - 1.45 * inch - 4])
            card.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, LINE), ("BACKGROUND", (0, 0), (0, -1), SOFT),
                                      ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
            story += [Spacer(1, 5), card]
        if (lk.get("count") or 0) > ROWS_SHOWN:
            story.append(r.p(f"First {ROWS_SHOWN} of {lk['count']} rows; the full set is in CTEM.", "small"))
        story.append(Spacer(1, 10))
