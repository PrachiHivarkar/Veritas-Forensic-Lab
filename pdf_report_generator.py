"""
PDF, TXT, and JSON Forensic Report Generator for VERITAS Forensic Lab.
Produces court-ready and investigation-grade documentation.
"""

import io
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether

def generate_text_report(analysis_data):
    """Generate structured text report (matches & upgrades the original format)."""
    fi = analysis_data.get("file_info", {})
    hashes = analysis_data.get("hashes", {})
    exif = analysis_data.get("exif", {})
    verdict = analysis_data.get("verdict", {})
    ela = analysis_data.get("ela", {})

    lines = [
        "================================================================================",
        "                  DIGITAL IMAGE FORENSICS INVESTIGATION REPORT",
        "                               VERITAS FORENSIC LAB",
        "================================================================================",
        f"Generated On   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Target File    : {fi.get('filename', 'Unknown')}",
        f"Overall Verdict: {verdict.get('risk_level', 'UNKNOWN')}",
        f"Authenticity   : {verdict.get('authenticity_score', 0)}% Confidence",
        f"Tamper Score   : {verdict.get('tampering_score', 0)}% Risk",
        "--------------------------------------------------------------------------------",
        "",
        "1. FILE EVIDENCE & INTEGRITY METRICS",
        "--------------------------------------------------------------------------------",
        f"File Name      : {fi.get('filename', 'N/A')}",
        f"File Size      : {fi.get('filesize_formatted', 'N/A')} ({fi.get('filesize_bytes', 0)} bytes)",
        f"Format         : {fi.get('format', 'N/A')}",
        f"Resolution     : {fi.get('resolution', 'N/A')}",
        f"Aspect Ratio   : {fi.get('aspect_ratio', 'N/A')}",
        f"Color Space    : {fi.get('color_mode', 'N/A')}",
        "",
        "2. CRYPTOGRAPHIC EVIDENCE HASHES",
        "--------------------------------------------------------------------------------",
        f"MD5            : {hashes.get('md5', 'N/A')}",
        f"SHA-1          : {hashes.get('sha1', 'N/A')}",
        f"SHA-256        : {hashes.get('sha256', 'N/A')}",
        f"SHA-512        : {hashes.get('sha512', 'N/A')}",
        "",
        "3. FORENSIC TAMPER ASSESSMENT & FINDINGS",
        "--------------------------------------------------------------------------------",
        f"Forensic Status: {verdict.get('risk_level', 'UNKNOWN')}",
    ]

    for f in verdict.get("findings", []):
        lines.append(f"  [{f.get('type', 'info').upper()}] {f.get('title')}: {f.get('detail')}")

    lines.extend([
        "",
        "4. ERROR LEVEL ANALYSIS (ELA) & PIXEL INTEGRITY",
        "--------------------------------------------------------------------------------",
        f"Quality Level Tested : {ela.get('quality_tested', 90)}%",
        f"Scale Factor Applied : {ela.get('scale_applied', 15)}x",
        f"Mean Error Rate      : {ela.get('mean_error', 0)}",
        f"Max Error Peak       : {ela.get('max_error', 0)}",
        f"Error Variance       : {ela.get('variance', 0)}",
        "",
        "5. EXIF & HARDWARE METADATA",
        "--------------------------------------------------------------------------------"
    ])

    if exif.get("has_exif"):
        cam = exif.get("camera", {})
        lines.append(f"Camera Make    : {cam.get('Make', 'Not Specified')}")
        lines.append(f"Camera Model   : {cam.get('Model', 'Not Specified')}")
        lines.append(f"Lens Model     : {cam.get('LensModel', 'Not Specified')}")
        lines.append(f"Software Tag   : {exif.get('software') or 'None detected'}")
        
        gps = exif.get("gps")
        if gps:
            lines.append(f"GPS Coordinates: {gps.get('latitude')}°, {gps.get('longitude')}° (Alt: {gps.get('altitude')}m)")
        else:
            lines.append("GPS Coordinates: No GPS geodata found")

        lines.append("\nRaw EXIF Tags:")
        for tag, val in exif.get("all_tags", {}).items():
            lines.append(f"  {tag:<28}: {val}")
    else:
        lines.append("No EXIF metadata was discovered in this image (metadata stripped or unsupported).")

    lines.extend([
        "",
        "================================================================================",
        "                                END OF REPORT",
        "  VERITAS FORENSIC SUITE • FOR INVESTIGATIVE AND VERIFICATION USE ONLY",
        "================================================================================"
    ])

    return "\n".join(lines)


def generate_pdf_report_bytes(analysis_data):
    """Generate a PDF report returned as in-memory bytes."""
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
    header_style = ParagraphStyle(
        'HeaderTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0f172a')
    )
    verdict_style = ParagraphStyle(
        'VerdictBadge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#ffffff')
    )

    story = []

    # Title & Header
    story.append(Paragraph("DIGITAL IMAGE FORENSICS REPORT", header_style))
    story.append(Paragraph(f"VERITAS Forensic Lab • Analysis Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

    fi = analysis_data.get("file_info", {})
    hashes = analysis_data.get("hashes", {})
    verdict = analysis_data.get("verdict", {})
    exif = analysis_data.get("exif", {})
    ela = analysis_data.get("ela", {})

    # Verdict Box Table
    v_color = colors.HexColor('#dc2626') if verdict.get('verdict_color') == 'danger' else (colors.HexColor('#d97706') if verdict.get('verdict_color') == 'warning' else colors.HexColor('#16a34a'))
    verdict_text = f"<b>VERDICT:</b> {verdict.get('risk_level', 'UNKNOWN')}<br/><b>Authenticity Confidence:</b> {verdict.get('authenticity_score', 0)}% &nbsp;&nbsp;|&nbsp;&nbsp; <b>Tamper Probability:</b> {verdict.get('tampering_score', 0)}%"
    verdict_table = Table([[Paragraph(verdict_text, verdict_style)]], colWidths=[540])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), v_color),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 12))

    # Section 1: File & Evidence Details
    story.append(Paragraph("1. EVIDENCE FILE METRICS", section_style))
    file_table_data = [
        [Paragraph("<b>File Name:</b>", body_style), Paragraph(str(fi.get('filename')), body_style), Paragraph("<b>Format:</b>", body_style), Paragraph(str(fi.get('format')), body_style)],
        [Paragraph("<b>File Size:</b>", body_style), Paragraph(f"{fi.get('filesize_formatted')} ({fi.get('filesize_bytes')} bytes)", body_style), Paragraph("<b>Resolution:</b>", body_style), Paragraph(f"{fi.get('resolution')} ({fi.get('aspect_ratio')})", body_style)],
        [Paragraph("<b>Color Mode:</b>", body_style), Paragraph(str(fi.get('color_mode')), body_style), Paragraph("<b>Analyzed At:</b>", body_style), Paragraph(str(fi.get('analysis_timestamp')), body_style)],
    ]
    t1 = Table(file_table_data, colWidths=[90, 180, 90, 180])
    t1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t1)
    story.append(Spacer(1, 12))

    # Section 2: Cryptographic Hashes
    story.append(Paragraph("2. CRYPTOGRAPHIC INTEGRITY HASHES", section_style))
    hash_data = [
        [Paragraph("<b>MD5</b>", body_style), Paragraph(hashes.get('md5', 'N/A'), code_style)],
        [Paragraph("<b>SHA-1</b>", body_style), Paragraph(hashes.get('sha1', 'N/A'), code_style)],
        [Paragraph("<b>SHA-256</b>", body_style), Paragraph(hashes.get('sha256', 'N/A'), code_style)],
        [Paragraph("<b>SHA-512</b>", body_style), Paragraph(hashes.get('sha512', 'N/A'), code_style)],
    ]
    t2 = Table(hash_data, colWidths=[90, 450])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t2)
    story.append(Spacer(1, 12))

    # Section 3: Forensic Tamper Analysis Findings
    story.append(Paragraph("3. KEY FORENSIC FINDINGS", section_style))
    findings_list = []
    for f in verdict.get("findings", []):
        color_bullet = "🔴" if f.get('type') == 'danger' else ("🟡" if f.get('type') == 'warning' else "🟢")
        item = f"{color_bullet} <b>{f.get('title')}:</b> {f.get('detail')}"
        findings_list.append([Paragraph(item, body_style)])
    
    if not findings_list:
        findings_list.append([Paragraph("No anomalies detected.", body_style)])

    t3 = Table(findings_list, colWidths=[540])
    t3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    story.append(t3)
    story.append(Spacer(1, 12))

    # Section 4: EXIF & Hardware
    story.append(Paragraph("4. METADATA & HARDWARE FINGERPRINT", section_style))
    cam = exif.get("camera", {})
    gps = exif.get("gps")
    gps_str = f"{gps['latitude']}°, {gps['longitude']}° (Alt: {gps.get('altitude')}m)" if gps else "No GPS coordinates embedded."

    exif_summary_data = [
        [Paragraph("<b>Camera Make/Model:</b>", body_style), Paragraph(f"{cam.get('Make', 'N/A')} {cam.get('Model', '')}", body_style)],
        [Paragraph("<b>Lens:</b>", body_style), Paragraph(cam.get('LensModel', 'N/A'), body_style)],
        [Paragraph("<b>Software Signature:</b>", body_style), Paragraph(exif.get('software') or "None detected", body_style)],
        [Paragraph("<b>GPS Coordinates:</b>", body_style), Paragraph(gps_str, body_style)],
        [Paragraph("<b>ELA Variance:</b>", body_style), Paragraph(f"{ela.get('variance', 0)} (Mean Error: {ela.get('mean_error', 0)})", body_style)],
    ]
    t4 = Table(exif_summary_data, colWidths=[140, 400])
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t4)
    story.append(Spacer(1, 15))

    # Legal Disclaimer / Footer
    disclaimer = Paragraph(
        "<b>DISCLAIMER:</b> This report is generated by automated digital forensic analysis algorithms including Error Level Analysis, cryptographic checksum validation, and EXIF consistency verification. Metadata indicators suggest potential editing or alterations but should be corroborated with secondary forensic procedures.",
        subtitle_style
    )
    story.append(disclaimer)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
