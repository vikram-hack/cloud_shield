"""Security Events routes"""
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user
from models import db, SecurityEvent, Alert, Incident
from config import Config

events_bp = Blueprint('events', __name__, url_prefix='/events')


@events_bp.route('/')
@login_required
def list_events():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '')
    category = request.args.get('category', '')
    source_ip = request.args.get('source_ip', '').strip()
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = SecurityEvent.query
    if q:
        query = query.filter(SecurityEvent.description.ilike(f'%{q}%'))
    if severity:
        query = query.filter_by(severity=severity)
    if category:
        query = query.filter_by(category=category)
    if source_ip:
        query = query.filter(SecurityEvent.source_ip.ilike(f'%{source_ip}%'))
    if date_from:
        try:
            df = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(SecurityEvent.timestamp >= df)
        except ValueError:
            pass
    if date_to:
        try:
            dt = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            query = query.filter(SecurityEvent.timestamp <= dt)
        except ValueError:
            pass

    pagination = query.order_by(SecurityEvent.timestamp.desc()).paginate(
        page=page, per_page=Config.EVENTS_PER_PAGE, error_out=False)

    categories = db.session.query(SecurityEvent.category).distinct().all()
    categories = [c[0] for c in categories if c[0]]

    return render_template('events/list.html',
                           pagination=pagination, events=pagination.items,
                           categories=categories, q=q, severity=severity,
                           category=category, source_ip=source_ip,
                           date_from=date_from, date_to=date_to)


@events_bp.route('/<int:eid>')
@login_required
def detail(eid):
    event = SecurityEvent.query.get_or_404(eid)
    related_alert = Alert.query.filter_by(event_id=eid).first()
    related_incident = Incident.query.get(event.incident_id) if event.incident_id else None
    return render_template('events/detail.html', event=event,
                           related_alert=related_alert,
                           related_incident=related_incident)
