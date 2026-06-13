#!/usr/bin/env python3
"""
GhostNet — Executive PDF Report Generator
Reads anomaly_detector cycle JSON → outputs professional SOC report PDF

Author: Eliezer Fuentes (enak223)
Usage: python3 report_generator.py ghostnet_anomaly_cycle_1.json
"""

import json, sys, glob
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Color palette ──────────────────────────────────────────────────────────────
DARK_BG    = colors.HexColor("#0d1117")
ACCENT     = colors.HexColor("#00d4aa")
RED        = colors.HexColor("#cc0000")
ORANGE     = colors.HexColor("#ff6600")
YELLOW     = colors.HexColor("#ffcc00")
LIGHT_GREY = colors.HexColor("#f4f4f4")
MID_GREY   = colors.HexColor("#cccccc")
DARK_GREY  = colors.HexColor("#333333")
WHITE      = colors.white

SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      colors.HexColor("#99cc00"),
    "INFO":     MID_GREY,
}

def sev_label(level):
    if level >= 12: return "CRITICAL"
    if level >= 9:  return "HIGH"
    if level >= 7:  return "MEDIUM"
    if level >= 4:  return "LOW"
    return "INFO"

def load_reports(paths):
    alerts = []
    for p in paths:
        try:
            data = json.loads(Path(p).read_text())
            alerts.extend(data.get("alerts", []))
        except Exception as e:
            print(f"[!] Failed to load {p}: {e}")
    return alerts

def build_stats(alerts):
    sev_counts = defaultdict(int)
    agent_counts = defaultdict(int)
    tactic_counts = defaultdict(int)
    tech_counts = defaultdict(lambda: {"name":"","count":0})
    top_alerts = []

    for a in alerts:
        lv = a.get("rule_level", 0)
        sl = sev_label(lv)
        sev_counts[sl] += 1
        agent_counts[a.get("agent_name","unknown")] += 1
        for m in a.get("mapped_mitre", []):
            tactic_counts[m.get("tactic","")] += 1
            tid = m.get("technique_id","")
            tech_counts[tid]["name"] = m.get("technique_name","")
            tech_counts[tid]["count"] += 1
        if lv >= 9:
            top_alerts.append(a)

    return {
        "sev_counts": dict(sev_counts),
        "agent_counts": dict(agent_counts),
        "tactic_counts": dict(tactic_counts),
        "tech_counts": tech_counts,
        "top_alerts": sorted(top_alerts, key=lambda x: -x.get("rule_level",0))[:10],
    }

def make_styles():
    base = getSampleStyleSheet()
    styles = {}
    styles["title"] = ParagraphStyle("title", fontSize=28, textColor=WHITE,
        fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=6)
    styles["subtitle"] = ParagraphStyle("subtitle", fontSize=12, textColor=ACCENT,
        fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4)
    styles["meta"] = ParagraphStyle("meta", fontSize=9, textColor=MID_GREY,
        fontName="Helvetica", alignment=TA_CENTER, spaceAfter=20)
    styles["section"] = ParagraphStyle("section", fontSize=14, textColor=ACCENT,
        fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=8)
    styles["body"] = ParagraphStyle("body", fontSize=9, textColor=DARK_GREY,
        fontName="Helvetica", spaceAfter=4, leading=14)
    styles["alert_desc"] = ParagraphStyle("alert_desc", fontSize=8, textColor=DARK_GREY,
        fontName="Helvetica", leading=12)
    styles["footer"] = ParagraphStyle("footer", fontSize=7, textColor=MID_GREY,
        fontName="Helvetica", alignment=TA_CENTER)
    return styles

def cover_block(styles, total, stats):
    els = []
    # Dark header background via table
    cover_data = [[Paragraph("GhostNet", styles["title"])],
                  [Paragraph("SOC Threat Detection Report", styles["subtitle"])],
                  [Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M UTC')}", styles["meta"])]]
    cover_table = Table(cover_data, colWidths=[6.5*inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("LEFTPADDING",   (0,0), (-1,-1), 20),
        ("RIGHTPADDING",  (0,0), (-1,-1), 20),
        ("ROUNDEDCORNERS", [8]),
    ]))
    els.append(cover_table)
    els.append(Spacer(1, 0.2*inch))

    # Executive summary metrics row
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    metric_data = [[
        Paragraph(f"<b>{total}</b><br/>Total Alerts", styles["body"]),
        *[Paragraph(f"<b>{stats['sev_counts'].get(s,0)}</b><br/>{s}", styles["body"])
          for s in sev_order]
    ]]
    metric_table = Table(metric_data, colWidths=[1.0*inch]*6)
    metric_style = [
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("BACKGROUND",  (0,0), (0,-1), LIGHT_GREY),
    ]
    for i, s in enumerate(sev_order, 1):
        c = SEV_COLORS.get(s, MID_GREY)
        metric_style.append(("BACKGROUND", (i,0), (i,-1), c))
        metric_style.append(("TEXTCOLOR",  (i,0), (i,-1), WHITE if s in ("CRITICAL","HIGH") else DARK_GREY))
    metric_table.setStyle(TableStyle(metric_style))
    els.append(metric_table)
    return els

def section_header(text, styles):
    return [
        Spacer(1, 0.1*inch),
        Paragraph(text, styles["section"]),
        HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=6),
    ]

def top_alerts_table(alerts, styles):
    headers = ["Severity","Agent","Level","Description","MITRE"]
    data = [headers]
    for a in alerts:
        lv = a.get("rule_level",0)
        sl = sev_label(lv)
        mitre = ", ".join(m.get("technique_id","") for m in a.get("mapped_mitre",[])[:2])
        desc = a.get("rule_description","")[:70] + ("…" if len(a.get("rule_description","")) > 70 else "")
        data.append([sl, a.get("agent_name","?"), str(lv),
                     Paragraph(desc, styles["alert_desc"]),
                     Paragraph(mitre, styles["alert_desc"])])

    t = Table(data, colWidths=[0.8*inch, 1.1*inch, 0.4*inch, 2.8*inch, 1.1*inch])
    ts = TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), DARK_BG),
        ("TEXTCOLOR",    (0,0), (-1,0), ACCENT),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, LIGHT_GREY]),
        ("GRID",         (0,0), (-1,-1), 0.3, MID_GREY),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ])
    for i, a in enumerate(alerts, 1):
        sl = sev_label(a.get("rule_level",0))
        c = SEV_COLORS.get(sl, MID_GREY)
        ts.add("BACKGROUND", (0,i), (0,i), c)
        ts.add("TEXTCOLOR",  (0,i), (0,i), WHITE if sl in ("CRITICAL","HIGH") else DARK_GREY)
        ts.add("FONTNAME",   (0,i), (0,i), "Helvetica-Bold")
    t.setStyle(ts)
    return t

def mitre_table(tech_counts, styles):
    data = [["Technique ID","Name","Hit Count"]]
    for tid, d in sorted(tech_counts.items(), key=lambda x: -x[1]["count"])[:15]:
        data.append([tid, d["name"], str(d["count"])])
    t = Table(data, colWidths=[1.2*inch, 4.0*inch, 1.0*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, LIGHT_GREY]),
        ("GRID",          (0,0), (-1,-1), 0.3, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("ALIGN",         (2,0), (2,-1), "CENTER"),
    ]))
    return t

def agent_table(agent_counts, styles):
    data = [["Agent","Alert Count"]]
    for agent, count in sorted(agent_counts.items(), key=lambda x: -x[1]):
        data.append([agent, str(count)])
    t = Table(data, colWidths=[3.5*inch, 2.7*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, LIGHT_GREY]),
        ("GRID",          (0,0), (-1,-1), 0.3, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("ALIGN",         (1,0), (1,-1), "CENTER"),
    ]))
    return t

def generate_pdf(alerts, outfile):
    stats = build_stats(alerts)
    styles = make_styles()
    doc = SimpleDocTemplate(outfile, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    els = []

    # Cover
    els += cover_block(styles, len(alerts), stats)
    els.append(Spacer(1, 0.2*inch))

    # Executive Summary
    els += section_header("Executive Summary", styles)
    crit = stats["sev_counts"].get("CRITICAL",0)
    high = stats["sev_counts"].get("HIGH",0)
    agents = len(stats["agent_counts"])
    techs = len(stats["tech_counts"])
    summary = (f"GhostNet detected <b>{len(alerts)} alerts</b> across <b>{agents} monitored agents</b> "
               f"in this reporting period. Of these, <b>{crit} CRITICAL</b> and <b>{high} HIGH</b> severity "
               f"alerts require immediate attention. The MITRE ATT&CK auto-mapper identified "
               f"<b>{techs} unique techniques</b> across the kill chain. "
               f"Priority focus areas: Initial Access, Execution, and Defense Evasion.")
    els.append(Paragraph(summary, styles["body"]))
    els.append(Spacer(1, 0.1*inch))

    # Top Alerts
    els += section_header("Top Priority Alerts", styles)
    if stats["top_alerts"]:
        els.append(top_alerts_table(stats["top_alerts"], styles))
    else:
        els.append(Paragraph("No HIGH/CRITICAL alerts in this period.", styles["body"]))
    els.append(Spacer(1, 0.1*inch))

    # MITRE Coverage
    els += section_header("MITRE ATT&CK Coverage", styles)
    if stats["tech_counts"]:
        els.append(mitre_table(stats["tech_counts"], styles))
    els.append(Spacer(1, 0.05*inch))
    els.append(Paragraph(
        f"Navigator layer available at: github.com/enak223/project-ghostnet",
        styles["body"]))

    # Agent Breakdown
    els += section_header("Alert Distribution by Agent", styles)
    els.append(agent_table(stats["agent_counts"], styles))

    # Recommendations
    els += section_header("Recommendations", styles)
    recs = [
        ("CRITICAL", "Investigate AppCompat Database launches on win11-workstation — "
         "cross-reference with T1546.011 persistence indicators and recent software installs."),
        ("HIGH", "Review multiple web 400 errors from single IPs — validate whether "
         "nikto/scanner activity represents authorized pen testing or external recon."),
        ("MEDIUM", "Harden CIS benchmark compliance on win11-workstation — current score "
         "below 30%. Priority: password policy, audit logging, sandbox restrictions."),
        ("MEDIUM", "Enable SSH on ubuntu-webserver to close NullByte brute force "
         "detection gap and achieve 100%% adversary simulation coverage."),
    ]
    for sev, text in recs:
        c = SEV_COLORS.get(sev, MID_GREY)
        rec_data = [[Paragraph(sev, styles["body"]), Paragraph(text, styles["body"])]]
        rec_t = Table(rec_data, colWidths=[0.9*inch, 5.8*inch])
        rec_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (0,-1), c),
            ("TEXTCOLOR",     (0,0), (0,-1), WHITE if sev in ("CRITICAL","HIGH") else DARK_GREY),
            ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("GRID",          (0,0), (-1,-1), 0.3, MID_GREY),
        ]))
        els.append(rec_t)
        els.append(Spacer(1, 0.05*inch))

    # Footer note
    els.append(Spacer(1, 0.2*inch))
    els.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY))
    els.append(Paragraph(
        f"GhostNet SOC Automation Platform | github.com/enak223/project-ghostnet | "
        f"Report generated {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        styles["footer"]))

    doc.build(els)
    print(f"[+] PDF report saved → {outfile}")

def main():
    if len(sys.argv) < 2:
        paths = sorted(glob.glob("ghostnet_anomaly_cycle_*.json"))
        if not paths:
            print("Usage: python3 report_generator.py <cycle_report.json>")
            sys.exit(1)
        print(f"[*] Auto-detected: {paths}")
    else:
        paths = sys.argv[1:]

    alerts = load_reports(paths)
    print(f"[*] Loaded {len(alerts)} alerts from {len(paths)} report(s)")

    outfile = f"ghostnet_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    generate_pdf(alerts, outfile)

if __name__ == "__main__":
    main()
