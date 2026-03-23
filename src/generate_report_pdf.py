import json
from pathlib import Path
from datetime import datetime
from collections import Counter

from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


ALERTS_PATH = Path("reports/alerts_enriched.json")
TICKETS_DIR = Path("reports/tickets")
OUTPUT_PATH = Path("reports/AI_SOC_Copilot_Report.pdf")


def load_alerts():
    if not ALERTS_PATH.exists():
        return []
    return json.loads(ALERTS_PATH.read_text(encoding="utf-8"))


def load_ticket_count():
    if not TICKETS_DIR.exists():
        return 0
    return len(list(TICKETS_DIR.glob("*.json")))


def severity_rank(sev: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get(str(sev).lower(), 0)


def build_summary(alerts):
    severity_counts = Counter([str(a.get("severity", "unknown")).lower() for a in alerts])
    detection_counts = Counter([a.get("detection_type", "unknown") for a in alerts])

    avg_rule_conf = round(
        sum(float(a.get("rule_confidence", 0.0)) for a in alerts) / max(len(alerts), 1), 3
    )
    avg_ai_conf = round(
        sum(float(a.get("ai_confidence", 0.0)) for a in alerts) / max(len(alerts), 1), 3
    )

    return {
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "detection_counts": detection_counts,
        "avg_rule_conf": avg_rule_conf,
        "avg_ai_conf": avg_ai_conf,
    }


def add_table(story, title, rows, col_widths=None):
    styles = getSampleStyleSheet()
    story.append(Paragraph(title, styles["Heading3"]))

    table = Table(rows, colWidths=col_widths)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 0.2 * inch))


def generate_pdf():
    alerts = load_alerts()
    ticket_count = load_ticket_count()
    summary = build_summary(alerts)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=LETTER,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "BodySmall",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
    )

    story = []

    # Title
    story.append(Paragraph("AI SOC Copilot - Technical Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", body))
    story.append(Spacer(1, 0.25 * inch))

    # Executive summary
    story.append(Paragraph("1. Executive Summary", styles["Heading2"]))
    story.append(
        Paragraph(
            "This report documents a Splunk-integrated AI SOC Copilot pipeline that detects "
            "security events, normalizes alerts, enriches with local LLM analysis, supports "
            "analyst triage workflow, and exports SOC tickets.",
            body,
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    # System overview
    story.append(Paragraph("2. System Architecture", styles["Heading2"]))
    story.append(
        Paragraph(
            "Pipeline: Splunk (BOTS) -> Detection Queries -> Alert Schema -> AI JSON Enrichment "
            "-> Streamlit Triage Dashboard -> Ticket JSON Export",
            body,
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    # KPI table
    story.append(Paragraph("3. KPI Snapshot", styles["Heading2"]))
    kpi_rows = [
        ["Metric", "Value"],
        ["Total Alerts", str(summary["total_alerts"])],
        ["Total Tickets", str(ticket_count)],
        ["Average Rule Confidence", str(summary["avg_rule_conf"])],
        ["Average AI Confidence", str(summary["avg_ai_conf"])],
    ]
    add_table(story, "Overall Metrics", kpi_rows, col_widths=[3.0 * inch, 2.0 * inch])

    # Severity table
    sev = summary["severity_counts"]
    sev_rows = [["Severity", "Count"]]
    for level in ["critical", "high", "medium", "low", "unknown"]:
        if sev.get(level, 0) > 0:
            sev_rows.append([level.capitalize(), str(sev[level])])
    add_table(story, "Alert Severity Distribution", sev_rows, col_widths=[3.0 * inch, 2.0 * inch])

    # Detection table
    det = summary["detection_counts"]
    det_rows = [["Detection Type", "Count"]]
    for k, v in det.items():
        det_rows.append([str(k), str(v)])
    add_table(story, "Detection Breakdown", det_rows, col_widths=[4.5 * inch, 1.0 * inch])

    # Methodology
    story.append(Paragraph("4. Detection + AI Methodology", styles["Heading2"]))
    story.append(
        Paragraph(
            "Detections are rule-driven in Splunk (ground truth). AI is used for structured "
            "incident explanation and recommended actions, with confidence separated into "
            "rule_confidence and ai_confidence.",
            body,
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    # Sample alerts
    story.append(Paragraph("5. Sample Alerts", styles["Heading2"]))
    sorted_alerts = sorted(
        alerts,
        key=lambda a: (severity_rank(a.get("severity", "")), a.get("timestamp", "")),
        reverse=True,
    )

    for idx, a in enumerate(sorted_alerts[:10], start=1):
        ai = a.get("ai_summary", {})

        story.append(Paragraph(f"Alert {idx}: {a.get('detection_type', 'Unknown')}", styles["Heading3"]))
        story.append(Paragraph(f"Alert ID: {a.get('alert_id', 'N/A')}", body))
        story.append(Paragraph(f"Severity: {a.get('severity', 'N/A')}", body))
        story.append(Paragraph(f"MITRE: {a.get('mitre_technique', 'N/A')}", body))
        story.append(Paragraph(f"Rule Confidence: {a.get('rule_confidence', 0.0)}", body))
        story.append(Paragraph(f"AI Confidence: {a.get('ai_confidence', 0.0)}", body))
        story.append(Paragraph(f"What happened: {ai.get('what_happened', 'N/A')}", body))
        story.append(Paragraph(f"Why it matters: {ai.get('why_it_matters', 'N/A')}", body))

        actions = ai.get("top_3_actions", [])
        if actions:
            story.append(Paragraph("Recommended Actions:", body))
            for act in actions[:3]:
                story.append(Paragraph(f"- {act}", body))

        timeline = a.get("investigation_timeline", [])
        if timeline:
            story.append(Paragraph("Timeline:", body))
            for t in timeline[:5]:
                story.append(Paragraph(f"- {t}", body))

        story.append(Spacer(1, 0.15 * inch))

    story.append(PageBreak())

    # Conclusion
    story.append(Paragraph("6. Conclusion and Next Steps", styles["Heading2"]))
    story.append(
        Paragraph(
            "The SOC Copilot demonstrates practical SOC workflow: multi-detection ingestion, "
            "structured AI triage summaries, analyst-in-the-loop status/labeling, and ticket export. "
            "Recommended next upgrades: add privilege escalation detection, automate scheduled runs, "
            "and integrate ticket push to enterprise systems.",
            body,
        )
    )

    doc.build(story)
    print(f"PDF generated: {OUTPUT_PATH.resolve()}")
if __name__ == "__main__":
    generate_pdf()
