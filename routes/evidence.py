"""Evidence Vault routes"""
import os
from datetime import datetime, timezone
from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, abort, send_file)
from flask_login import login_required, current_user
from models import db, Evidence, Incident
from modules.evidence_manager import store_evidence, verify_evidence, get_evidence_file_path
from modules.audit_logger import log_action

evidence_bp = Blueprint('evidence', __name__, url_prefix='/evidence')

ALLOWED_TYPES = ['log_export', 'auth_record', 'config_snapshot', 'investigation_report', 'other']


@evidence_bp.route('/')
@login_required
def list_evidence():
    incident_id = request.args.get('incident_id', type=int)
    ev_type = request.args.get('type', '')
    integrity = request.args.get('integrity', '')

    query = Evidence.query
    if incident_id:
        query = query.filter_by(incident_id=incident_id)
    if ev_type:
        query = query.filter_by(evidence_type=ev_type)
    if integrity:
        query = query.filter_by(integrity_status=integrity)

    items = query.order_by(Evidence.collection_timestamp.desc()).all()
    incidents = Incident.query.order_by(Incident.created_at.desc()).all()

    return render_template('evidence/list.html',
                           items=items, incidents=incidents,
                           allowed_types=ALLOWED_TYPES,
                           incident_id=incident_id, ev_type=ev_type, integrity=integrity)


@evidence_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not current_user.is_analyst():
        abort(403)
    incidents = Incident.query.filter(Incident.status.notin_(['resolved', 'closed'])).all()

    if request.method == 'POST':
        file = request.files.get('file')
        ev_type = request.form.get('evidence_type', 'other')
        description = request.form.get('description', '').strip()[:500]
        incident_id = request.form.get('incident_id', type=int) or None

        if not file or file.filename == '':
            flash('No file selected.', 'danger')
            return render_template('evidence/upload.html', incidents=incidents,
                                   allowed_types=ALLOWED_TYPES)

        try:
            ev = store_evidence(
                file_stream=file,
                original_filename=file.filename,
                evidence_type=ev_type,
                description=description,
                incident_id=incident_id,
                collector=current_user,
            )
            flash(f'Evidence collected. SHA-256: {ev.sha256_hash}', 'success')
            return redirect(url_for('evidence.detail', eid=ev.id))
        except ValueError as e:
            flash(str(e), 'danger')

    return render_template('evidence/upload.html', incidents=incidents, allowed_types=ALLOWED_TYPES)


@evidence_bp.route('/<int:eid>')
@login_required
def detail(eid):
    ev = Evidence.query.get_or_404(eid)
    handling = ev.handling_actions.order_by('timestamp').all()
    incident = Incident.query.get(ev.incident_id) if ev.incident_id else None
    return render_template('evidence/detail.html', ev=ev, handling=handling, incident=incident)


@evidence_bp.route('/<int:eid>/verify', methods=['POST'])
@login_required
def verify(eid):
    if not current_user.is_analyst():
        abort(403)
    ev = Evidence.query.get_or_404(eid)
    result = verify_evidence(ev.evidence_id, actor=current_user)
    if result['status'] == 'verified':
        flash(f'✓ Integrity verified. SHA-256 matches recorded hash.', 'success')
    elif result['status'] == 'tampered':
        flash(f'⚠ INTEGRITY FAILURE: {result["message"]}', 'danger')
    else:
        flash(f'Evidence file missing from disk.', 'danger')
    return redirect(url_for('evidence.detail', eid=eid))


@evidence_bp.route('/<int:eid>/download')
@login_required
def download(eid):
    if not current_user.is_analyst():
        abort(403)
    ev = Evidence.query.get_or_404(eid)
    try:
        filepath = get_evidence_file_path(ev.evidence_id, actor=current_user)
        log_action('evidence_downloaded', target_type='evidence', target_id=ev.evidence_id)
        return send_file(filepath, as_attachment=True,
                         download_name=ev.original_filename)
    except FileNotFoundError:
        flash('Evidence file not found on disk.', 'danger')
        return redirect(url_for('evidence.detail', eid=eid))
