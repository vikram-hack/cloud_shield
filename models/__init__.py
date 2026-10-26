"""
CloudShield Database Models
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─── User & Auth ─────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), nullable=False, default='viewer')  # admin, analyst, viewer
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    is_demo = db.Column(db.Boolean, default=False)

    incidents = db.relationship('Incident', backref='assigned_analyst', lazy='dynamic',
                                foreign_keys='Incident.assigned_to')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_analyst(self):
        return self.role in ('admin', 'analyst')

    def __repr__(self):
        return f'<User {self.username}>'


# ─── Cloud Resources ──────────────────────────────────────────────────────────

class CloudResource(db.Model):
    __tablename__ = 'cloud_resources'

    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False)
    resource_type = db.Column(db.String(64), nullable=False)  # vm, bucket, iam_user, etc.
    region = db.Column(db.String(64), default='local-sim-1')
    owner = db.Column(db.String(128))
    status = db.Column(db.String(32), default='active')  # active, stopped, isolated, deleted
    is_public = db.Column(db.Boolean, default=False)
    encryption_enabled = db.Column(db.Boolean, default=True)
    logging_enabled = db.Column(db.Boolean, default=True)
    config_json = db.Column(db.Text, default='{}')  # JSON blob for type-specific config
    risk_score = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_demo = db.Column(db.Boolean, default=False)

    findings = db.relationship('SecurityFinding', backref='resource', lazy='dynamic')

    def __repr__(self):
        return f'<CloudResource {self.name}>'


# ─── Security Findings ────────────────────────────────────────────────────────

class SecurityFinding(db.Model):
    __tablename__ = 'security_findings'

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.String(64), unique=True, nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('cloud_resources.id'), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(32), nullable=False)  # critical, high, medium, low, info
    risk_score = db.Column(db.Float, default=0.0)
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    status = db.Column(db.String(32), default='open')  # open, remediated, accepted
    detected_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    is_demo = db.Column(db.Boolean, default=False)


# ─── Security Events ──────────────────────────────────────────────────────────

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    source_ip = db.Column(db.String(64))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(64))  # denormalized for speed
    http_method = db.Column(db.String(16))
    endpoint = db.Column(db.String(512))
    category = db.Column(db.String(64), nullable=False, index=True)
    detection_rule = db.Column(db.String(128))
    severity = db.Column(db.String(32), nullable=False, index=True)
    description = db.Column(db.Text)
    raw_data = db.Column(db.Text)   # sanitized metadata, no credentials
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=True)
    is_demo = db.Column(db.Boolean, default=False)

    user = db.relationship('User', foreign_keys=[user_id])
    alert = db.relationship('Alert', backref='event', uselist=False)


# ─── Alerts ───────────────────────────────────────────────────────────────────

class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey('security_events.id'), nullable=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=True)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(32), nullable=False, index=True)
    status = db.Column(db.String(32), default='new', index=True)  # new, acknowledged, investigating, resolved, false_positive
    source_ip = db.Column(db.String(64))
    category = db.Column(db.String(64))
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    notes = db.Column(db.Text)
    false_positive_reason = db.Column(db.Text)
    is_demo = db.Column(db.Boolean, default=False)

    assignee = db.relationship('User', foreign_keys=[assigned_to])


# ─── Incidents ────────────────────────────────────────────────────────────────

class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), default='open', index=True)  # open, investigating, contained, resolved, closed
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolution_summary = db.Column(db.Text)
    is_demo = db.Column(db.Boolean, default=False)

    events = db.relationship('SecurityEvent', backref='incident', lazy='dynamic',
                             foreign_keys='SecurityEvent.incident_id')
    alerts = db.relationship('Alert', backref='incident', lazy='dynamic',
                              foreign_keys='Alert.incident_id')
    notes = db.relationship('IncidentNote', backref='incident', lazy='dynamic',
                             order_by='IncidentNote.created_at')
    evidence_items = db.relationship('Evidence', backref='incident', lazy='dynamic')
    response_actions = db.relationship('ResponseAction', backref='incident', lazy='dynamic')


class IncidentNote(db.Model):
    __tablename__ = 'incident_notes'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    author = db.relationship('User', foreign_keys=[author_id])


# ─── Evidence ─────────────────────────────────────────────────────────────────

class Evidence(db.Model):
    __tablename__ = 'evidence'

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=True)
    evidence_type = db.Column(db.String(64), nullable=False)  # log_export, auth_record, config_snapshot, report
    original_filename = db.Column(db.String(256), nullable=False)
    stored_filename = db.Column(db.String(256), nullable=False, unique=True)
    collection_timestamp = db.Column(db.DateTime, default=utcnow, nullable=False)
    collected_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)
    integrity_status = db.Column(db.String(32), default='verified')  # verified, tampered, unverified
    last_verified = db.Column(db.DateTime, nullable=True)
    is_demo = db.Column(db.Boolean, default=False)

    collector = db.relationship('User', foreign_keys=[collected_by])
    handling_actions = db.relationship('EvidenceHandling', backref='evidence', lazy='dynamic')


class EvidenceHandling(db.Model):
    __tablename__ = 'evidence_handling'

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    action = db.Column(db.String(64), nullable=False)  # collected, verified, accessed, exported
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow, nullable=False)
    result = db.Column(db.String(32))
    notes = db.Column(db.Text)

    actor = db.relationship('User', foreign_keys=[actor_id])


# ─── Response Actions ─────────────────────────────────────────────────────────

class ResponseAction(db.Model):
    __tablename__ = 'response_actions'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=True)
    triggering_event_id = db.Column(db.Integer, db.ForeignKey('security_events.id'), nullable=True)
    rule_name = db.Column(db.String(128))
    action_type = db.Column(db.String(64), nullable=False)
    target_type = db.Column(db.String(64))   # user, resource, session
    target_id = db.Column(db.String(128))
    description = db.Column(db.Text)
    executed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    executed_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    result = db.Column(db.String(32))
    is_reversed = db.Column(db.Boolean, default=False)
    reversed_at = db.Column(db.DateTime, nullable=True)
    reversed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    executor = db.relationship('User', foreign_keys=[executed_by])


# ─── Audit Log ────────────────────────────────────────────────────────────────

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    actor_username = db.Column(db.String(64))
    action = db.Column(db.String(128), nullable=False)
    target_type = db.Column(db.String(64))
    target_id = db.Column(db.String(128))
    result = db.Column(db.String(32))
    metadata_json = db.Column(db.Text, default='{}')
    source_ip = db.Column(db.String(64))

    actor = db.relationship('User', foreign_keys=[actor_id])


# ─── Detection Rules ──────────────────────────────────────────────────────────

class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(64))
    severity = db.Column(db.String(32))
    pattern = db.Column(db.Text)
    threshold = db.Column(db.Integer, default=1)
    window_seconds = db.Column(db.Integer, default=300)
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
