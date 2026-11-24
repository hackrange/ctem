"""One alert as a printable PDF, on the same engine as the hunt report (api/hunt/report_pdf.py): the logo, the alert's
headline facts, the AI read and the story, the attack map, the details and process tree as wrapped cards, indicators,
files, network and DNS, the timeline, the alerts tied to it and the updates made from CTEM. Everything stays inside the
page margins; every piece of text is escaped before it becomes markup."""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from api.core.attack_map import drawing
from api.hunt.report_pdf import FRAME_W, LINE, MARGIN, SEV, SOFT, _fonts, _logo, _pages, _Report

CELL_MAX = 1500


def _cards(r: _Report, pairs: list[tuple[str, object]]) -> Table | None:
    rows = [[r.p(k, "small", 60), r.p(v, "cell", CELL_MAX)] for k, v in pairs if v not in (None, "", [], {})]
    if not rows:
        return None
    t = Table(rows, colWidths=[1.55 * inch, FRAME_W - 1.55 * inch - 4])
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, LINE), ("BACKGROUND", (0, 0), (0, -1), SOFT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def _proc_pairs(label: str, p: dict) -> list[tuple[str, object]]:
    return [(label, p.get("filename") or p.get("filepath")), ("Path", p.get("filepath")), ("Command line", p.get("cmdline")),
            ("User", p.get("user")), ("PID", p.get("pid")), ("Started", p.get("start")), ("Ended", p.get("end")),
            ("SHA256", p.get("sha256")), ("SHA1", p.get("sha1")), ("MD5", p.get("md5"))]


def build(a: dict, meta: dict) -> bytes:
    """a: the alert as the detail endpoint returns it; meta: generated, prepared_by, app_title, org_name, accent_color,
    logo_url, light_logo_url."""
    font, bold, mono, uni = _fonts()
    r = _Report(uni, (font, bold, mono))
    s, d = r.s, a.get("detail") or {}
    sev = (a.get("severity") or "medium").lower()
    sep = " &nbsp;·&nbsp; " if uni else " | "
    story = [Spacer(1, 1.05 * inch - 0.35 * inch), r.p(a.get("title") or "Alert", "title", 300),
             Paragraph(sep.join(x for x in [f'<font color="{SEV.get(sev, "#5f6b7a")}"><b>{r.t(sev.upper())}</b></font>',
                                            f"Status {r.t((a.get('status') or 'unknown').replace('_', ' '))}",
                                            r.t(a.get("source") or ""), f"Host {r.t(a.get('hostname') or 'unknown')}",
                                            f"Detected {r.t(a.get('detected_at') or 'unknown')}", "Confidential"] if x), s["meta"])]
    if a.get("link"):
        story.append(Paragraph(f'<link href="{r.t(a["link"])}" color="#1f5fbf">Open in CrowdStrike</link>', s["meta"]))
    if a.get("accepted_by"):
        e = a["accepted_by"]
        story.append(r.p(f"Accepted as expected by {e.get('created_by')} until {str(e.get('expires_at') or '')[:10]}: {e.get('reason')}", "meta"))
    read = (a.get("ai") or {}).get("read")
    if read:
        story.append(r.p("AI READ", "h2"))
        story.append(Paragraph(f"<b>{r.t(str(read.get('verdict') or '').replace('_', ' ').capitalize())}.</b> {r.t(read.get('summary'))}", s["body"]))
        for title, items in (("Why", read.get("why")), ("Check next", read.get("next_steps"))):
            if items:
                story.append(Paragraph(f"<b>{r.t(title)}:</b> " + "; ".join(r.t(i) for i in items), s["body"]))
        story.append(r.p("An AI's first read from the alert's names and MITRE data only. Check it before acting on it.", "small"))
    if a.get("story") or a.get("description"):
        story.append(r.p("WHAT HAPPENED", "h2"))
        box = Table([[[r.p(a.get("story") or a.get("description"))] + ([Spacer(1, 4), r.p(a["description"], "small")]
                                                                       if a.get("story") and a.get("description") else [])]],
                    colWidths=[FRAME_W])
        box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(meta["accent_color"])),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
        story.append(box)
    g = a.get("graph")
    if g and g.get("nodes") and len(g["nodes"]) > 1:
        width = FRAME_W if g["h"] * FRAME_W / (g["w"] + 40) <= 4.6 * inch else 4.6 * inch * (g["w"] + 40) / g["h"]
        story.append(KeepTogether([r.p("ATTACK PATH", "h2"), drawing(g, min(width, FRAME_W), font, bold)]))
    u, h, c = d.get("user") or {}, d.get("host") or {}, a.get("ctem_device") or {}
    details = [("Source", a.get("source")), ("Host", a.get("hostname")), ("Detected", a.get("detected_at")),
               ("MITRE", " / ".join(x for x in (a.get("tactic_id"), a.get("tactic"), a.get("technique_id"), a.get("technique")) if x)),
               ("IOA name", d.get("ioa_name")), ("Objective", d.get("objective")),
               ("User", f"{u['domain']}\\{u['name']}" if u.get("domain") and u.get("name") else u.get("name")),
               ("User SID", u.get("sid")), ("Host OS", " / ".join(x for x in (h.get("platform"), h.get("os_version")) if x)),
               ("Internal IP", h.get("local_ip")), ("External IP", h.get("external_ip")), ("Domain / site", " / ".join(x for x in (h.get("domain"), h.get("site")) if x)),
               ("Containment", h.get("containment")), ("Assigned to", d.get("assigned_to")), ("Resolution", d.get("resolution")),
               ("CTEM risk", f"{c.get('risk_grade') or ''} {c.get('risk_score') if c.get('risk_score') is not None else ''}".strip() or None),
               ("Open findings on host", c.get("open_findings")), ("Alert ID", (a.get("id") or "").removeprefix("threat_alert_"))]
    details += [(k.replace("_", " ").replace(".", " ").capitalize(), v) for k, v in (d.get("context") or [])]
    t = _cards(r, details)
    if t:
        story += [r.p("DETAILS", "h2"), t]
    procs = [(label, d.get(k)) for label, k in (("Grandparent", "grandparent"), ("Parent", "parent"),
                                                ("Process that triggered it", "process")) if d.get(k)]
    if procs:
        story.append(r.p("PROCESS TREE", "h2"))
        for label, p in procs:
            t = _cards(r, _proc_pairs(label, p))
            if t:
                story += [KeepTogether(t), Spacer(1, 5)]
    ind = []
    if d.get("ioc"):
        ind.append(("Indicator", f"{d['ioc'].get('type') or ''}: {d['ioc'].get('value') or ''} {d['ioc'].get('description') or ''}".strip()))
    for title, key in (("Quarantined", "quarantined"), ("Files written", "files_written"), ("Files it went after", "files_accessed"),
                       ("Documents opened", "documents")):
        items = d.get(key) or []
        if items:
            ind.append((title, "; ".join(str(f.get("filepath") or f.get("filename") or "") + (f" ({f['sha256']})" if f.get("sha256") else "")
                                         for f in items[:30])))
    if d.get("disposition"):
        ind.append(("What the EDR did", "; ".join(x for x in [", ".join(a.get("actions_text") or []), d["disposition"].get("summary")] if x)))
    t = _cards(r, ind)
    if t:
        story += [r.p("INDICATORS AND FILES", "h2"), t]
    net = [(str(n.get("at") or "")[:19], f"{n.get('direction') or ''} {n.get('remote')}:{n.get('remote_port')} {n.get('protocol') or ''}".strip())
           for n in (d.get("network") or [])[:40]]
    net += [(str(x.get("at") or "")[:19], f"DNS {x.get('domain')} ({x.get('type') or ''})") for x in (d.get("dns") or [])[:40]]
    t = _cards(r, net)
    if t:
        story += [r.p("NETWORK AND DNS", "h2"), t]
    tl = a.get("timeline") or []
    if tl:
        story.append(r.p("TIMELINE", "h2"))
        for e in tl[:80]:
            story.append(Paragraph(f'<font color="#5f6b7a">{r.t(str(e.get("at") or "")[:19].replace("T", " "))}</font> &nbsp; <b>{r.t(e.get("title"))}</b>'
                                   + (f'<br/><font size="8">{r.t(e.get("text"), 600)}</font>' if e.get("text") else ""),
                                   ParagraphStyle("tl", parent=s["cell"], spaceAfter=4, leftIndent=8)))
    tied = [x for x in (a.get("steps") or []) if not x.get("current")]
    if tied:
        story.append(r.p("TIED TO THIS ALERT", "h2"))
        for x in tied[:40]:
            times = f"{x.get('count')} times, {str(x.get('first') or '')[:16]} to {str(x.get('last') or '')[:16]}" if (x.get("count") or 1) > 1 \
                else str(x.get("first") or "")[:16]
            story.append(Paragraph(f"<b>{r.t(x.get('title'))}</b> &nbsp; {r.t(x.get('severity'))} &nbsp; {r.t(x.get('hostname'))} "
                                   f"&nbsp; <font color=\"#5f6b7a\">{r.t(x.get('why'))}; {r.t(times)}</font>",
                                   ParagraphStyle("tied", parent=s["cell"], spaceAfter=3)))
    ups = a.get("updates") or []
    if ups:
        story.append(r.p("UPDATES MADE FROM CTEM", "h2"))
        for x in ups[:30]:
            story.append(Paragraph(f"{r.t(str(x.get('at') or '')[:16].replace('T', ' '))} &nbsp; <b>{r.t(x.get('by'))}</b> &nbsp; "
                                   f"{r.t(' '.join(v for v in (x.get('status'), x.get('classification')) if v) or 'comment')} &nbsp; "
                                   f"{r.t(x.get('state'))}{(': ' + r.t(x.get('comment'), 400)) if x.get('comment') else ''}",
                                   ParagraphStyle("up", parent=s["cell"], spaceAfter=3)))
    dot = "  ·  " if uni else " | "
    footer = r.plain(dot.join([f"{meta['app_title']} Cyber Threats", f"Generated {meta['generated']} by {meta['prepared_by']}", "Confidential"]))
    label = r.plain("Security alert report" + (dot + meta["org_name"] if meta.get("org_name") else ""))
    first, later = _pages(_logo(meta.get("logo_url")), _logo(meta.get("light_logo_url")), label, meta["accent_color"], footer, font, bold)
    out = io.BytesIO()
    SimpleDocTemplate(out, pagesize=letter, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=0.7 * inch, bottomMargin=0.7 * inch,
                      title=r.plain(f"Alert: {a.get('title') or ''}"[:200]), author=r.plain(meta["app_title"]),
                      creator="open-ctem").build(story, onFirstPage=first, onLaterPages=later)
    return out.getvalue()
