"""Dashboard/Overview routes"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from models import (db, CloudResource, SecurityFinding, SecurityEvent,
                    Alert, Incident, Evidence)

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
@dashboard_bp.route('/dashboard/')
@login_required
def overview():
    # Time filter
    period = request.args.get('period', '7d')
    period_map = {'24h': 1, '7d': 7, '30d': 30}
    days = period_map.get(period, 7)
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    # Metric cards
    total_resources = CloudResource.query.filter(CloudResource.status != 'deleted').count()
    high_risk = CloudResource.query.filter(
        CloudResource.risk_score >= 6.0, CloudResource.status != 'deleted'
    ).count()
    events_count = SecurityEvent.query.filter(SecurityEvent.timestamp >= since).count()
    open_alerts = Alert.query.filter(Alert.status.in_(['new', 'acknowledged'])).count()
    critical_incidents = Incident.query.filter(
        Incident.severity == 'critical',
        Incident.status.notin_(['resolved', 'closed'])
    ).count()

    # Evidence integrity
    total_ev = Evidence.query.count()
    tampered_ev = Evidence.query.filter_by(integrity_status='tampered').count()
    evidence_ok = tampered_ev == 0 and total_ev > 0
    evidence_status = 'OK' if evidence_ok else ('TAMPERED' if tampered_ev > 0 else 'NO DATA')

    # Recent events
    recent_events = SecurityEvent.query.order_by(
        SecurityEvent.timestamp.desc()
    ).limit(10).all()

    # Recent critical alerts
    recent_alerts = Alert.query.filter(
        Alert.severity.in_(['critical', 'high']),
        Alert.status.notin_(['resolved', 'false_positive'])
    ).order_by(Alert.created_at.desc()).limit(5).all()

    # High risk resources
    high_risk_resources = CloudResource.query.filter(
        CloudResource.risk_score >= 6.0, CloudResource.status != 'deleted'
    ).order_by(CloudResource.risk_score.desc()).limit(5).all()

    # Active incidents
    active_incidents = Incident.query.filter(
        Incident.status.notin_(['resolved', 'closed'])
    ).order_by(Incident.created_at.desc()).limit(5).all()

    # Chart data: events by day
    events_by_day = []
    for i in range(days):
        day = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days - 1 - i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day.replace(hour=23, minute=59, second=59, microsecond=999999)
        count = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= day_start,
            SecurityEvent.timestamp <= day_end
        ).count()
        events_by_day.append({'date': day.strftime('%b %d'), 'count': count})

    # Chart data: alerts by severity
    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).group_by(Alert.severity).all()
    alerts_by_severity = {s: c for s, c in severity_counts}

    # Chart data: event categories
    cat_counts = db.session.query(
        SecurityEvent.category, func.count(SecurityEvent.id)
    ).filter(SecurityEvent.timestamp >= since).group_by(SecurityEvent.category).all()
    events_by_category = {c: n for c, n in cat_counts}

    # Chart data: resource risk distribution
    risk_dist = {
        'critical': CloudResource.query.filter(CloudResource.risk_score >= 8.0, CloudResource.status != 'deleted').count(),
        'high': CloudResource.query.filter(CloudResource.risk_score >= 6.0, CloudResource.risk_score < 8.0, CloudResource.status != 'deleted').count(),
        'medium': CloudResource.query.filter(CloudResource.risk_score >= 4.0, CloudResource.risk_score < 6.0, CloudResource.status != 'deleted').count(),
        'low': CloudResource.query.filter(CloudResource.risk_score > 0, CloudResource.risk_score < 4.0, CloudResource.status != 'deleted').count(),
        'clean': CloudResource.query.filter(
            (CloudResource.risk_score == 0) | (CloudResource.risk_score == None) | (CloudResource.risk_score <= 0.0),
            CloudResource.status != 'deleted'
        ).count(),
    }

    # Incident status distribution
    inc_dist = db.session.query(
        Incident.status, func.count(Incident.id)
    ).group_by(Incident.status).all()
    incidents_by_status = {s: c for s, c in inc_dist}

    return render_template('dashboard/overview.html',
        period=period,
        total_resources=total_resources,
        high_risk=high_risk,
        events_count=events_count,
        open_alerts=open_alerts,
        critical_incidents=critical_incidents,
        evidence_status=evidence_status,
        tampered_ev=tampered_ev,
        recent_events=recent_events,
        recent_alerts=recent_alerts,
        high_risk_resources=high_risk_resources,
        active_incidents=active_incidents,
        events_by_day=events_by_day,
        alerts_by_severity=alerts_by_severity,
        events_by_category=events_by_category,
        risk_dist=risk_dist,
        incidents_by_status=incidents_by_status,
    )
