"""Incidents routes"""
import uuid
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from models import db, Incident, IncidentNote, Alert, SecurityEvent, User, Evidence
from modules.audit_logger import log_action
from config import Config

incidents_bp = Blueprint('incidents', __name__, url_prefix='/incidents')

STATUSES = ['open', 'investigating', 'contained', 'resolved', 'closed']


@incidents_bp.route('/')
@login_required
def list_incidents():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    q = request.args.get('q', '').strip()

    query = Incident.query
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if q:
        query = query.filter(Incident.title.ilike(f'%{q}%'))

    pagination = query.order_by(Incident.created_at.desc()).paginate(
        page=page, per_page=Config.INCIDENTS_PER_PAGE, error_out=False)

    return render_template('incidents/list.html',
                           pagination=pagination, incidents=pagination.items,
                           severity=severity, status=status, q=q, statuses=STATUSES)


@incidents_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if not current_user.is_analyst():
        abort(403)
    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()[:256]
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'medium')
        assigned_to = request.form.get('assigned_to', type=int)

        if not title:
            flash('Incident title is required.', 'danger')
            return render_template('incidents/form.html', analysts=analysts)

        inc = Incident(
            incident_id=f'INC-{datetime.now(timezone.utc).strftime("%Y")}-{uuid.uuid4().hex[:4].upper()}',
            title=title, description=description, severity=severity,
            status='open', assigned_to=assigned_to or None,
        )
        db.session.add(inc)
        db.session.commit()
        log_action('incident_created', target_type='incident', target_id=inc.incident_id)
        flash(f'Incident {inc.incident_id} created.', 'success')
        return redirect(url_for('incidents.detail', iid=inc.id))

    return render_template('incidents/form.html', analysts=analysts)


@incidents_bp.route('/<int:iid>')
@login_required
def detail(iid):
    inc = Incident.query.get_or_404(iid)
    events = inc.events.order_by(SecurityEvent.timestamp.asc()).all()
    alerts = inc.alerts.order_by(Alert.created_at.desc()).all()
    notes = inc.notes.all()
    evidence_items = inc.evidence_items.all()
    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()
    unlinked_events = SecurityEvent.query.filter_by(incident_id=None).order_by(
        SecurityEvent.timestamp.desc()).limit(50).all()
    unlinked_alerts = Alert.query.filter_by(incident_id=None).order_by(
        Alert.created_at.desc()).limit(50).all()
    return render_template('incidents/detail.html', inc=inc, events=events,
                           alerts=alerts, notes=notes, evidence_items=evidence_items,
                           analysts=analysts, unlinked_events=unlinked_events,
                           unlinked_alerts=unlinked_alerts, statuses=STATUSES)


@incidents_bp.route('/<int:iid>/update-status', methods=['POST'])
@login_required
def update_status(iid):
    if not current_user.is_analyst():
        abort(403)
    inc = Incident.query.get_or_404(iid)
    new_status = request.form.get('status', '')
    if new_status in STATUSES:
        inc.status = new_status
        inc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if new_status in ('resolved', 'closed'):
            inc.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None)
            inc.resolution_summary = request.form.get('resolution_summary', '').strip()
        db.session.commit()
        log_action('incident_status_changed', target_type='incident', target_id=inc.incident_id,
                   metadata={'new_status': new_status})
        flash(f'Incident status updated to {new_status}.', 'success')
    return redirect(url_for('incidents.detail', iid=iid))


@incidents_bp.route('/<int:iid>/add-note', methods=['POST'])
@login_required
def add_note(iid):
    if not current_user.is_analyst():
        abort(403)
    inc = Incident.query.get_or_404(iid)
    content = request.form.get('content', '').strip()
    if content:
        note = IncidentNote(incident_id=inc.id, author_id=current_user.id, content=content)
        db.session.add(note)
        inc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()
        flash('Note added.', 'success')
    return redirect(url_for('incidents.detail', iid=iid))


@incidents_bp.route('/<int:iid>/link-event', methods=['POST'])
@login_required
def link_event(iid):
    if not current_user.is_analyst():
        abort(403)
    inc = Incident.query.get_or_404(iid)
    event_id = request.form.get('event_id', type=int)
    event = SecurityEvent.query.get_or_404(event_id)
    event.incident_id = inc.id
    inc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('event_linked_to_incident', target_type='incident', target_id=inc.incident_id,
               metadata={'event_id': event_id})
    flash('Event linked to incident.', 'success')
    return redirect(url_for('incidents.detail', iid=iid))


@incidents_bp.route('/<int:iid>/link-alert', methods=['POST'])
@login_required
def link_alert(iid):
    if not current_user.is_analyst():
        abort(403)
    inc = Incident.query.get_or_404(iid)
    alert_id = request.form.get('alert_id', type=int)
    alert = Alert.query.get_or_404(alert_id)
    alert.incident_id = inc.id
    inc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('alert_linked_to_incident', target_type='incident', target_id=inc.incident_id,
               metadata={'alert_id': alert_id})
    flash('Alert linked to incident.', 'success')
    return redirect(url_for('incidents.detail', iid=iid))


@incidents_bp.route('/<int:iid>/assign', methods=['POST'])
@login_required
def assign(iid):
    if not current_user.is_analyst():
        abort(403)
    inc = Incident.query.get_or_404(iid)
    analyst_id = request.form.get('analyst_id', type=int)
    inc.assigned_to = analyst_id
    inc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('incident_assigned', target_type='incident', target_id=inc.incident_id)
    flash('Incident assigned.', 'success')
    return redirect(url_for('incidents.detail', iid=iid))
