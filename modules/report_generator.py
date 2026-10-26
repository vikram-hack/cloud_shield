"""
CloudShield Report Generator (ReportLab)
"""
import io
import uuid
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ─── Color Palette ────────────────────────────────────────────────────────────
DARK_BG = colors.HexColor('#0B1220')
NEON_GREEN = colors.HexColor('#39FF88')
CYAN = colors.HexColor('#22D3EE')
CRITICAL_RED = colors.HexColor('#FF4D6D')
AMBER = colors.HexColor('#FBBF24')
SLATE = colors.HexColor('#1E293B')
LIGHT_TEXT = colors.HexColor('#F1F5F9')
MUTED = colors.HexColor('#94A3B8')
WHITE = colors.white
BLACK = colors.black

SEVERITY_COLORS = {
    'critical': CRITICAL_RED,
    'high': colors.HexColor('#F97316'),
    'medium': AMBER,
    'low': colors.HexColor('#22C55E'),
    'info': CYAN,
}


def _styles():
    base = getSampleStyleSheet()
    custom = {
        'title': ParagraphStyle('cs_title', parent=base['Title'],
                                textColor=WHITE, fontSize=20, spaceAfter=6),
        'subtitle': ParagraphStyle('cs_subtitle', parent=base['Normal'],
                                   textColor=MUTED, fontSize=10, spaceAfter=12),
        'heading': ParagraphStyle('cs_heading', parent=base['Heading2'],
                                  textColor=NEON_GREEN, fontSize=13, spaceBefore=14, spaceAfter=4),
        'body': ParagraphStyle('cs_body', parent=base['Normal'],
                               textColor=LIGHT_TEXT, fontSize=9, leading=14),
        'small': ParagraphStyle('cs_small', parent=base['Normal'],
                                textColor=MUTED, fontSize=8, leading=12),
        'code': ParagraphStyle('cs_code', parent=base['Code'],
                               textColor=CYAN, fontSize=8, leading=11),
    }
    return custom


def _header_table(report_type, report_id, generated_at, generated_by):
    s = _styles()
    data = [
        [Paragraph('☁ CloudShield', s['title']),
         Paragraph(f'<b>{report_type}</b>', ParagraphStyle('rtype', textColor=CYAN, fontSize=14, alignment=TA_RIGHT))],
        [Paragraph('LOCAL LAB | SIMULATED ENVIRONMENT', s['small']),
         Paragraph(f'Report ID: {report_id}', ParagraphStyle('rid', textColor=MUTED, fontSize=8, alignment=TA_RIGHT))],
        [Paragraph(f'Generated: {generated_at} UTC | By: {generated_by}', s['small']), ''],
    ]
    t = Table(data, colWidths=[10 * cm, 8 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), DARK_BG),
        ('TEXTCOLOR', (0, 0), (-1, -1), LIGHT_TEXT),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (0, -1), 6),
        ('RIGHTPADDING', (-1, 0), (-1, -1), 6),
    ]))
    return t


def _severity_cell(sev):
    c = SEVERITY_COLORS.get(sev.lower(), MUTED)
    return Paragraph(f'<b>{sev.upper()}</b>',
                     ParagraphStyle('sev', textColor=c, fontSize=8))


def _disclaimer():
    s = _styles()
    return Paragraph(
        '⚠ IMPORTANT: All findings in this report relate to the local simulated environment only. '
        'CloudShield does not connect to real cloud providers. Evidence SHA-256 hashes verify '
        'content integrity relative to the recorded hash; they do not independently establish '
        'provenance or prove the complete chain of custody.',
        ParagraphStyle('disc', textColor=AMBER, fontSize=8, leading=12,
                       borderColor=AMBER, borderWidth=0.5, borderPadding=6,
                       backColor=colors.HexColor('#1C1200'))
    )


# ─── Report: Incident Investigation ──────────────────────────────────────────

def generate_incident_report(incident, current_user) -> bytes:
    """Generate a PDF incident investigation report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    s = _styles()
    report_id = str(uuid.uuid4())[:8].upper()
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')
    elements = []

    elements.append(_header_table('INCIDENT INVESTIGATION REPORT', report_id, now_str, current_user.username))
    elements.append(HRFlowable(color=NEON_GREEN, thickness=1, spaceAfter=10))
    elements.append(_disclaimer())
    elements.append(Spacer(1, 12))

    # Incident summary
    elements.append(Paragraph('INCIDENT SUMMARY', s['heading']))
    summary_data = [
        ['Incident ID', incident.incident_id],
        ['Title', incident.title],
        ['Severity', incident.severity.upper()],
        ['Status', incident.status.upper()],
        ['Assigned To', incident.assigned_analyst.username if incident.assigned_analyst else 'Unassigned'],
        ['Created', str(incident.created_at)[:19] + ' UTC'],
        ['Last Updated', str(incident.updated_at)[:19] + ' UTC'],
    ]
    t = Table(summary_data, colWidths=[5 * cm, 13 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), SLATE),
        ('BACKGROUND', (1, 0), (1, -1), DARK_BG),
        ('TEXTCOLOR', (0, 0), (-1, -1), LIGHT_TEXT),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.3, MUTED),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 10))

    if incident.description:
        elements.append(Paragraph('Description', s['heading']))
        elements.append(Paragraph(incident.description, s['body']))

    # Events
    events = list(incident.events.order_by('timestamp').all())
    if events:
        elements.append(Paragraph('RELATED SECURITY EVENTS', s['heading']))
        ev_data = [['Timestamp (UTC)', 'Category', 'Severity', 'Source IP', 'Description']]
        for ev in events[:50]:
            ev_data.append([
                str(ev.timestamp)[:19],
                ev.category or '',
                ev.severity or '',
                ev.source_ip or '',
                (ev.description or '')[:60],
            ])
        t = Table(ev_data, colWidths=[4 * cm, 3 * cm, 2 * cm, 3 * cm, 6 * cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), SLATE),
            ('TEXTCOLOR', (0, 0), (-1, 0), NEON_GREEN),
            ('BACKGROUND', (0, 1), (-1, -1), DARK_BG),
            ('TEXTCOLOR', (0, 1), (-1, -1), LIGHT_TEXT),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.2, MUTED),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [DARK_BG, SLATE]),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 10))

    # Evidence
    evidence_items = list(incident.evidence_items.all())
    if evidence_items:
        elements.append(Paragraph('EVIDENCE INVENTORY', s['heading']))
        ev_data = [['Evidence ID', 'Type', 'Filename', 'SHA-256 Hash', 'Integrity', 'Collected']]
        for ev in evidence_items:
            ev_data.append([
                ev.evidence_id[:8],
                ev.evidence_type,
                ev.original_filename,
                ev.sha256_hash[:16] + '...',
                ev.integrity_status,
                str(ev.collection_timestamp)[:10],
            ])
        t = Table(ev_data, colWidths=[2.5 * cm, 2.5 * cm, 3 * cm, 4 * cm, 2 * cm, 2.5 * cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), SLATE),
            ('TEXTCOLOR', (0, 0), (-1, 0), NEON_GREEN),
            ('BACKGROUND', (0, 1), (-1, -1), DARK_BG),
            ('TEXTCOLOR', (0, 1), (-1, -1), LIGHT_TEXT),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.2, MUTED),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 10))

    # Notes
    notes = list(incident.notes.all())
    if notes:
        elements.append(Paragraph('INVESTIGATION NOTES', s['heading']))
        for note in notes:
            elements.append(Paragraph(
                f'<b>{note.author.username}</b> at {str(note.created_at)[:19]} UTC:',
                s['small']))
            elements.append(Paragraph(note.content, s['body']))
            elements.append(Spacer(1, 6))

    # Resolution
    if incident.resolution_summary:
        elements.append(Paragraph('RESOLUTION SUMMARY', s['heading']))
        elements.append(Paragraph(incident.resolution_summary, s['body']))

    # Footer note
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(color=MUTED, thickness=0.5))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f'CloudShield v1.0.0 | Report generated {now_str} UTC | Environment: LOCAL LAB',
        ParagraphStyle('footer', textColor=MUTED, fontSize=7, alignment=TA_CENTER)))

    doc.build(elements)
    buf.seek(0)
    return buf.read()


def generate_posture_report(findings, current_user) -> bytes:
    """Generate a PDF security posture assessment report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    s = _styles()
    report_id = str(uuid.uuid4())[:8].upper()
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')
    elements = []

    elements.append(_header_table('CLOUD SECURITY POSTURE REPORT', report_id, now_str, current_user.username))
    elements.append(HRFlowable(color=NEON_GREEN, thickness=1, spaceAfter=10))
    elements.append(_disclaimer())
    elements.append(Spacer(1, 12))

    elements.append(Paragraph('FINDINGS SUMMARY', s['heading']))
    from collections import Counter
    sev_counts = Counter(f.severity for f in findings)
    summary_data = [['Severity', 'Count']] + [[sev.title(), str(cnt)] for sev, cnt in sev_counts.items()]
    t = Table(summary_data, colWidths=[8 * cm, 10 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SLATE),
        ('TEXTCOLOR', (0, 0), (-1, 0), NEON_GREEN),
        ('BACKGROUND', (0, 1), (-1, -1), DARK_BG),
        ('TEXTCOLOR', (0, 1), (-1, -1), LIGHT_TEXT),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.3, MUTED),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph('DETAILED FINDINGS', s['heading']))
    for f in findings:
        resource = f.resource
        block = [
            Paragraph(f'<b>[{f.severity.upper()}]</b> {f.title}', s['body']),
            Paragraph(f'Finding ID: {f.finding_id} | Resource: {resource.name} ({resource.resource_type}) | Score: {f.risk_score}', s['small']),
            Paragraph(f.description, s['body']),
            Paragraph(f'<b>Remediation:</b> {f.remediation}', s['small']),
            Spacer(1, 8),
        ]
        elements.extend(block)

    doc.build(elements)
    buf.seek(0)
    return buf.read()


def generate_events_report(events, current_user, title='Security Event Summary') -> bytes:
    """Generate a PDF security events summary report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    s = _styles()
    report_id = str(uuid.uuid4())[:8].upper()
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')
    elements = []

    elements.append(_header_table(title.upper(), report_id, now_str, current_user.username))
    elements.append(HRFlowable(color=NEON_GREEN, thickness=1, spaceAfter=10))
    elements.append(_disclaimer())
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f'Total Events: {len(events)}', s['body']))
    elements.append(Spacer(1, 8))

    ev_data = [['Timestamp (UTC)', 'Category', 'Severity', 'Source IP', 'Rule', 'Description']]
    for ev in events[:200]:
        ev_data.append([
            str(ev.timestamp)[:19],
            ev.category or '',
            ev.severity or '',
            ev.source_ip or '',
            ev.detection_rule or '',
            (ev.description or '')[:50],
        ])
    t = Table(ev_data, colWidths=[3.5 * cm, 2.5 * cm, 2 * cm, 2.5 * cm, 3 * cm, 4.5 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SLATE),
        ('TEXTCOLOR', (0, 0), (-1, 0), NEON_GREEN),
        ('BACKGROUND', (0, 1), (-1, -1), DARK_BG),
        ('TEXTCOLOR', (0, 1), (-1, -1), LIGHT_TEXT),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('GRID', (0, 0), (-1, -1), 0.2, MUTED),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [DARK_BG, SLATE]),
    ]))
    elements.append(t)

    doc.build(elements)
    buf.seek(0)
    return buf.read()


def generate_evidence_integrity_report(evidence_items, current_user) -> bytes:
    """Generate a PDF evidence integrity report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    s = _styles()
    report_id = str(uuid.uuid4())[:8].upper()
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')
    elements = []

    elements.append(_header_table('EVIDENCE INTEGRITY REPORT', report_id, now_str, current_user.username))
    elements.append(HRFlowable(color=NEON_GREEN, thickness=1, spaceAfter=10))
    elements.append(_disclaimer())
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(
        'SHA-256 hashes verify that file content has not been modified since the recorded hash was computed. '
        'This report does not independently establish provenance or prove the complete chain of custody.',
        s['small']))
    elements.append(Spacer(1, 10))

    ev_data = [['Evidence ID', 'Filename', 'SHA-256 Hash (Full)', 'Integrity', 'Last Verified']]
    for ev in evidence_items:
        ev_data.append([
            ev.evidence_id[:12],
            ev.original_filename,
            ev.sha256_hash,
            ev.integrity_status,
            str(ev.last_verified)[:19] + ' UTC' if ev.last_verified else 'Never',
        ])
    t = Table(ev_data, colWidths=[3 * cm, 4 * cm, 7 * cm, 2 * cm, 2.5 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SLATE),
        ('TEXTCOLOR', (0, 0), (-1, 0), NEON_GREEN),
        ('BACKGROUND', (0, 1), (-1, -1), DARK_BG),
        ('TEXTCOLOR', (0, 1), (-1, -1), LIGHT_TEXT),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('GRID', (0, 0), (-1, -1), 0.2, MUTED),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('WORDWRAP', (2, 1), (2, -1), True),
    ]))
    elements.append(t)

    doc.build(elements)
    buf.seek(0)
    return buf.read()
