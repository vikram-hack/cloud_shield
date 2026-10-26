"""Digital Forensics routes"""
from datetime import datetime, timezone
from flask import Blueprint, render_template, request
from flask_login import login_required
from models import db, SecurityEvent, Alert, Incident, CloudResource, User

forensics_bp = Blueprint('forensics', __name__, url_prefix='/forensics')


@forensics_bp.route('/')
@login_required
def overview():
    # Filters
    incident_id = request.args.get('incident_id', type=int)
    username = request.args.get('username', '').strip()
    source_ip = request.args.get('source_ip', '').strip()
    resource_id = request.args.get('resource_id', type=int)
    category = request.args.get('category', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    query = SecurityEvent.query
    if incident_id:
        query = query.filter_by(incident_id=incident_id)
    if username:
        query = query.filter(SecurityEvent.username.ilike(f'%{username}%'))
    if source_ip:
        query = query.filter(SecurityEvent.source_ip.ilike(f'%{source_ip}%'))
    if category:
        query = query.filter_by(category=category)
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

    timeline = query.order_by(SecurityEvent.timestamp.asc()).limit(500).all()

    # Correlation: identify suspicious sequences
    correlations = _correlate(timeline)

    incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    categories = db.session.query(SecurityEvent.category).distinct().all()
    categories = [c[0] for c in categories if c[0]]
    resources = CloudResource.query.filter(CloudResource.status != 'deleted').all()

    return render_template('forensics/overview.html',
                           timeline=timeline,
                           correlations=correlations,
                           incidents=incidents,
                           categories=categories,
                           resources=resources,
                           incident_id=incident_id,
                           username=username,
                           source_ip=source_ip,
                           category=category,
                           date_from=date_from,
                           date_to=date_to)


def _correlate(events):
    """
    Basic heuristic correlation: identify IPs with both failures and successes.
    Returns list of correlation notices with uncertainty noted.
    NOTE: Matching IP alone does not confirm same attacker.
    """
    correlations = []
    ip_categories = {}
    for ev in events:
        ip = ev.source_ip or 'unknown'
        ip_categories.setdefault(ip, set()).add(ev.category)

    for ip, cats in ip_categories.items():
        if 'auth_failure' in cats and 'auth_success' in cats:
            correlations.append({
                'type': 'failure_then_success',
                'ip': ip,
                'description': (
                    f'IP {ip} has both authentication failures and successes. '
                    'This may indicate successful brute-force or credential-stuffing. '
                    'Note: matching IP does not confirm same actor.'
                ),
                'severity': 'high',
                'uncertainty': 'Correlation based on shared source IP only.',
            })
        if 'sql_injection' in cats or 'xss_attempt' in cats:
            correlations.append({
                'type': 'attack_pattern',
                'ip': ip,
                'description': f'IP {ip} triggered web attack detection rules.',
                'severity': 'high',
                'uncertainty': 'Automated detection. Manual review required.',
            })

    return correlations
