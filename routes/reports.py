"""Reports routes"""
import io
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, abort, send_file, flash, redirect, url_for
from flask_login import login_required, current_user
from models import db, Incident, SecurityFinding, SecurityEvent, Evidence, Alert
from modules.report_generator import (generate_incident_report, generate_posture_report,
                                       generate_events_report, generate_evidence_integrity_report)
from modules.audit_logger import log_action

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


@reports_bp.route('/')
@login_required
def overview():
    incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    return render_template('reports/overview.html', incidents=incidents)


@reports_bp.route('/incident/<int:iid>')
@login_required
def incident_report(iid):
    inc = Incident.query.get_or_404(iid)
    pdf = generate_incident_report(inc, current_user)
    log_action('report_generated', target_type='incident', target_id=inc.incident_id,
               metadata={'report_type': 'incident_investigation'})
    filename = f'cloudshield_incident_{inc.incident_id}_{datetime.now(timezone.utc).strftime("%Y%m%d")}.pdf'
    return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                     as_attachment=True, download_name=filename)


@reports_bp.route('/posture')
@login_required
def posture_report():
    severity = request.args.get('severity', '')
    query = SecurityFinding.query.filter_by(status='open')
    if severity:
        query = query.filter_by(severity=severity)
    findings = query.order_by(SecurityFinding.risk_score.desc()).all()
    pdf = generate_posture_report(findings, current_user)
    log_action('report_generated', result='success', metadata={'report_type': 'posture', 'findings': len(findings)})
    filename = f'cloudshield_posture_{datetime.now(timezone.utc).strftime("%Y%m%d")}.pdf'
    return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                     as_attachment=True, download_name=filename)


@reports_bp.route('/events')
@login_required
def events_report():
    days = request.args.get('days', 7, type=int)
    from datetime import timedelta
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    events = SecurityEvent.query.filter(SecurityEvent.timestamp >= since).order_by(
        SecurityEvent.timestamp.desc()).all()
    pdf = generate_events_report(events, current_user, title=f'Security Events – Last {days} Days')
    log_action('report_generated', result='success', metadata={'report_type': 'events', 'count': len(events)})
    filename = f'cloudshield_events_{datetime.now(timezone.utc).strftime("%Y%m%d")}.pdf'
    return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                     as_attachment=True, download_name=filename)


@reports_bp.route('/evidence-integrity')
@login_required
def evidence_report():
    items = Evidence.query.order_by(Evidence.collection_timestamp.desc()).all()
    pdf = generate_evidence_integrity_report(items, current_user)
    log_action('report_generated', result='success',
               metadata={'report_type': 'evidence_integrity', 'count': len(items)})
    filename = f'cloudshield_evidence_integrity_{datetime.now(timezone.utc).strftime("%Y%m%d")}.pdf'
    return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                     as_attachment=True, download_name=filename)
