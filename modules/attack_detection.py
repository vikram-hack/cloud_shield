"""
CloudShield Attack Detection Engine
"""
import re
import uuid
from datetime import datetime, timezone, timedelta
from flask import request
from models import db, SecurityEvent, Alert, DetectionRule

# ─── Detection Patterns ───────────────────────────────────────────────────────

SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
    r"(--|#|/\*)",
    r"(\bOR\b\s+\d+=\d+)",
    r"('\s*(OR|AND)\s*'[^']*'='[^']*')",
    r"(;\s*(DROP|DELETE|INSERT|UPDATE)\b)",
    r"(\bxp_cmdshell\b)",
    r"(\bINFORMATION_SCHEMA\b)",
]

XSS_PATTERNS = [
    r"(<\s*script[^>]*>)",
    r"(javascript\s*:)",
    r"(on(load|error|click|mouseover|focus|blur|change|submit|keyup|keydown)\s*=)",
    r"(<\s*(iframe|object|embed|applet|form)[^>]*>)",
    r"(document\.(cookie|write|location))",
    r"(eval\s*\()",
    r"(alert\s*\()",
]

TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\)",
    r"(%2e%2e[/%5c])",
    r"(\.\.%2f|\.\.%5c)",
    r"(/etc/passwd|/etc/shadow)",
    r"(\\windows\\system32)",
]


def _compile(patterns):
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_SQL_RE = _compile(SQL_INJECTION_PATTERNS)
_XSS_RE = _compile(XSS_PATTERNS)
_TRAV_RE = _compile(TRAVERSAL_PATTERNS)


def _check_patterns(value, patterns):
    """Return first matching pattern string or None."""
    for pat in patterns:
        m = pat.search(str(value))
        if m:
            return m.group(0)[:80]
    return None


def _create_event(category, severity, description, detection_rule,
                  source_ip=None, user_id=None, username=None,
                  method=None, endpoint=None, raw_data=None, is_demo=False):
    """Persist a SecurityEvent and optionally generate an Alert."""
    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        source_ip=source_ip,
        user_id=user_id,
        username=username,
        http_method=method,
        endpoint=endpoint,
        category=category,
        detection_rule=detection_rule,
        severity=severity,
        description=description,
        raw_data=raw_data or '',
        is_demo=is_demo,
    )
    db.session.add(event)
    db.session.flush()  # get event.id

    # Auto-generate alert for medium+ severity
    if severity in ('critical', 'high', 'medium'):
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            event_id=event.id,
            title=description[:200],
            description=description,
            severity=severity,
            status='new',
            source_ip=source_ip,
            category=category,
            is_demo=is_demo,
        )
        db.session.add(alert)

    db.session.commit()
    return event


# ─── Public Detection API ─────────────────────────────────────────────────────

def inspect_request(user_id=None, username=None):
    """
    Analyse the current Flask request for attack indicators.
    Call this from a before_request hook or route handler.
    Returns list of detected event IDs.
    """
    detected = []
    source_ip = request.remote_addr
    method = request.method
    endpoint = request.path[:256]

    # Collect all input values to inspect
    inputs = {}
    try:
        inputs.update(request.args.to_dict(flat=True))
        if request.form:
            inputs.update(request.form.to_dict(flat=True))
        if request.is_json and request.json:
            inputs.update({k: str(v) for k, v in request.json.items()})
    except Exception:
        pass

    for field, value in inputs.items():
        safe_field = field[:64]
        # SQL Injection
        match = _check_patterns(value, _SQL_RE)
        if match:
            ev = _create_event(
                category='sql_injection',
                severity='high',
                description=f'Possible SQL injection in field "{safe_field}": matched pattern "{match}"',
                detection_rule='SQLi-Pattern-001',
                source_ip=source_ip, user_id=user_id, username=username,
                method=method, endpoint=endpoint,
                raw_data=f'field={safe_field}',
            )
            detected.append(ev.event_id)

        # XSS
        match = _check_patterns(value, _XSS_RE)
        if match:
            ev = _create_event(
                category='xss_attempt',
                severity='high',
                description=f'Possible XSS in field "{safe_field}": matched pattern "{match}"',
                detection_rule='XSS-Pattern-001',
                source_ip=source_ip, user_id=user_id, username=username,
                method=method, endpoint=endpoint,
                raw_data=f'field={safe_field}',
            )
            detected.append(ev.event_id)

        # Path traversal
        match = _check_patterns(value, _TRAV_RE)
        if match:
            ev = _create_event(
                category='path_traversal',
                severity='high',
                description=f'Path traversal attempt in field "{safe_field}": "{match}"',
                detection_rule='TRAV-Pattern-001',
                source_ip=source_ip, user_id=user_id, username=username,
                method=method, endpoint=endpoint,
                raw_data=f'field={safe_field}',
            )
            detected.append(ev.event_id)

    return detected


def record_failed_login(username, source_ip):
    """Record a failed login and check for brute-force threshold."""
    from config import Config
    window = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15)
    recent_failures = SecurityEvent.query.filter(
        SecurityEvent.category == 'auth_failure',
        SecurityEvent.source_ip == source_ip,
        SecurityEvent.timestamp >= window,
    ).count()

    severity = 'low'
    rule = 'AUTH-FAIL-001'
    if recent_failures >= Config.MAX_LOGIN_ATTEMPTS - 1:
        severity = 'high'
        rule = 'AUTH-BRUTE-001'

    _create_event(
        category='auth_failure',
        severity=severity,
        description=f'Failed login attempt for user "{username}" from {source_ip}. '
                    f'({recent_failures + 1} failures in last 15 min)',
        detection_rule=rule,
        source_ip=source_ip,
        username=username,
        method='POST',
        endpoint='/auth/login',
    )


def record_successful_login(user_id, username, source_ip):
    """Record a successful login event."""
    _create_event(
        category='auth_success',
        severity='info',
        description=f'Successful login for user "{username}" from {source_ip}',
        detection_rule='AUTH-OK-001',
        source_ip=source_ip,
        user_id=user_id,
        username=username,
        method='POST',
        endpoint='/auth/login',
    )


def record_unauthorized_access(endpoint, source_ip, user_id=None, username=None):
    """Record an unauthorized access attempt."""
    _create_event(
        category='unauthorized_access',
        severity='medium',
        description=f'Unauthorized access attempt to "{endpoint}" from {source_ip}',
        detection_rule='AUTHZ-DENY-001',
        source_ip=source_ip,
        user_id=user_id,
        username=username,
        method=request.method,
        endpoint=endpoint,
    )


def create_demo_event(category, severity, description, rule, source_ip,
                      username=None, method='GET', endpoint='/'):
    """Create a synthetic demonstration event (clearly marked is_demo=True)."""
    return _create_event(
        category=category, severity=severity, description=description,
        detection_rule=rule, source_ip=source_ip, username=username,
        method=method, endpoint=endpoint, is_demo=True,
    )
