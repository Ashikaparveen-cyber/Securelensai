"""
PDF Report Generator Module
Generates downloadable ReportLab PDF security assessment reports.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


def generate_scan_pdf_report(scan_data: dict) -> bytes:
    """Generate a PDF report binary for a scan result."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#1b1f34")
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#8b7bff"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b")
    )
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    story = []

    # Header Banner
    url = scan_data.get("url", "Target URL")
    scan_id = scan_data.get("scan_id", "N/A")
    timestamp = scan_data.get("timestamp", datetime.utcnow().isoformat())
    risk = scan_data.get("risk", {})
    score = risk.get("overall_score", 0)
    risk_level = risk.get("risk_level", "Unknown")

    story.append(Paragraph("🛡️ SECURELENS AI — SECURITY REPORT", title_style))
    story.append(Paragraph(f"Automated Cybersecurity Audit & AI Vulnerability Assessment | Date: {timestamp}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#8b7bff"), spaceAfter=15))

    # Executive Overview Box
    overview_data = [
        [Paragraph("<b>Target URL:</b>", body_style), Paragraph(url, body_style)],
        [Paragraph("<b>Scan ID:</b>", body_style), Paragraph(scan_id, body_style)],
        [Paragraph("<b>Security Risk Score:</b>", body_style), Paragraph(f"<b>{score} / 100</b> ({risk_level})", body_style)],
    ]

    overview_table = Table(overview_data, colWidths=[1.8 * inch, 5.2 * inch])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 15))

    # AI Executive Summary (if present)
    ai_summary = scan_data.get("ai_analysis") or scan_data.get("ai_summary")
    if ai_summary and isinstance(ai_summary, str):
        story.append(Paragraph("AI Analyst Assessment", h2_style))
        story.append(Paragraph(ai_summary, body_style))
        story.append(Spacer(1, 15))

    # Vulnerabilities Table
    findings = risk.get("all_findings", [])
    story.append(Paragraph(f"Identified Vulnerabilities ({len(findings)})", h2_style))

    if findings:
        table_data = [[
            Paragraph("Severity", table_header_style),
            Paragraph("Category", table_header_style),
            Paragraph("Finding / Vulnerability", table_header_style),
            Paragraph("Recommendation", table_header_style),
        ]]

        for f in findings:
            sev = f.get("severity", "info").upper()
            cat = f.get("category", "Scanner")
            name = f.get("name", f.get("msg", ""))
            rec = f.get("recommendation", "N/A")

            # Color coding severity
            if sev == "CRITICAL":
                sev_p = Paragraph(f"<font color='#dc2626'><b>{sev}</b></font>", body_style)
            elif sev == "HIGH":
                sev_p = Paragraph(f"<font color='#d97706'><b>{sev}</b></font>", body_style)
            elif sev == "MEDIUM":
                sev_p = Paragraph(f"<font color='#ca8a04'><b>{sev}</b></font>", body_style)
            else:
                sev_p = Paragraph(f"<font color='#16a34a'><b>{sev}</b></font>", body_style)

            table_data.append([
                sev_p,
                Paragraph(cat, body_style),
                Paragraph(name, body_style),
                Paragraph(rec, body_style)
            ])

        vuln_table = Table(table_data, colWidths=[1.1 * inch, 1.6 * inch, 2.3 * inch, 2.0 * inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1b1f34")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(vuln_table)
    else:
        story.append(Paragraph("No critical vulnerabilities were detected during this scan.", body_style))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
    story.append(Paragraph("Generated automatically by SecureLens AI Platform.", subtitle_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
