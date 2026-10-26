"""Alerts routes"""
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from models import db, Alert, Incident, User, SecurityEvent
from modules.audit_logger import log_action
from config import Config

alerts_bp = Blueprint('alerts', __name__, url_prefix='/alerts')


@alerts_bp.route('/')
@login_required
def list_alerts():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    category = request.args.get('category', '')
    q = request.args.get('q', '').strip()

    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if category:
        query = query.filter_by(category=category)
    if q:
        query = query.filter(Alert.title.ilike(f'%{q}%'))

    pagination = query.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=Config.ALERTS_PER_PAGE, error_out=False)

    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()
    incidents = Incident.query.filter(Incident.status.notin_(['resolved', 'closed'])).all()

    return render_template('alerts/list.html',
                           pagination=pagination, alerts=pagination.items,
                           analysts=analysts, incidents=incidents,
                           severity=severity, status=status, category=category, q=q)


@alerts_bp.route('/<int:aid>')
@login_required
def detail(aid):
    alert = Alert.query.get_or_404(aid)
    event = SecurityEvent.query.get(alert.event_id) if alert.event_id else None
    incident = Incident.query.get(alert.incident_id) if alert.incident_id else None
    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()
    incidents = Incident.query.filter(Incident.status.notin_(['resolved', 'closed'])).all()
    return render_template('alerts/detail.html', alert=alert, event=event,
                           incident=incident, analysts=analysts, incidents=incidents)


@alerts_bp.route('/<int:aid>/acknowledge', methods=['POST'])
@login_required
def acknowledge(aid):
    if not current_user.is_analyst():
        abort(403)
    alert = Alert.query.get_or_404(aid)
    alert.status = 'acknowledged'
    alert.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('alert_acknowledged', target_type='alert', target_id=alert.alert_id)
    flash('Alert acknowledged.', 'success')
    return redirect(request.referrer or url_for('alerts.list_alerts'))


@alerts_bp.route('/<int:aid>/investigate', methods=['POST'])
@login_required
def start_investigate(aid):
    if not current_user.is_analyst():
        abort(403)
    alert = Alert.query.get_or_404(aid)
    alert.status = 'investigating'
    alert.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('alert_investigating', target_type='alert', target_id=alert.alert_id)
    flash('Alert marked as under investigation.', 'info')
    return redirect(request.referrer or url_for('alerts.list_alerts'))


@alerts_bp.route('/<int:aid>/resolve', methods=['POST'])
@login_required
def resolve(aid):
    if not current_user.is_analyst():
        abort(403)
    alert = Alert.query.get_or_404(aid)
    alert.status = 'resolved'
    note = request.form.get('note', '').strip()[:1000]
    if note:
        alert.notes = (alert.notes or '') + f'\n[{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")} UTC] {current_user.username}: {note}'
    alert.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('alert_resolved', target_type='alert', target_id=alert.alert_id)
    flash('Alert resolved.', 'success')
    return redirect(request.referrer or url_for('alerts.list_alerts'))


@alerts_bp.route('/<int:aid>/false-positive', methods=['POST'])
@login_required
def false_positive(aid):
    if not current_user.is_analyst():
        abort(403)
    alert = Alert.query.get_or_404(aid)
    reason = request.form.get('reason', '').strip()[:500]
    alert.status = 'false_positive'
    alert.false_positive_reason = reason
    alert.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('alert_false_positive', target_type='alert', target_id=alert.alert_id,
               metadata={'reason': reason})
    flash('Alert marked as false positive.', 'info')
    return redirect(request.referrer or url_for('alerts.list_alerts'))


@alerts_bp.route('/<int:aid>/assign', methods=['POST'])
@login_required
def assign(aid):
    if not current_user.is_analyst():
        abort(403)
    alert = Alert.query.get_or_404(aid)
    analyst_id = request.form.get('analyst_id', type=int)
    incident_id = request.form.get('incident_id', type=int)
    if analyst_id:
        alert.assigned_to = analyst_id
    if incident_id:
        alert.incident_id = incident_id
    alert.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('alert_assigned', target_type='alert', target_id=alert.alert_id)
    flash('Alert updated.', 'success')
    return redirect(request.referrer or url_for('alerts.detail', aid=aid))


@alerts_bp.route('/<int:aid>/note', methods=['POST'])
@login_required
def add_note(aid):
    if not current_user.is_analyst():
        abort(403)
    alert = Alert.query.get_or_404(aid)
    note = request.form.get('note', '').strip()[:1000]
    if note:
        alert.notes = (alert.notes or '') + f'\n[{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")} UTC] {current_user.username}: {note}'
        alert.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()
        flash('Note added.', 'success')
    return redirect(url_for('alerts.detail', aid=aid))
