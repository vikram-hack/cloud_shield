"""
CloudShield Risk Assessment Engine
"""
import uuid
import json
from datetime import datetime, timezone
from models import db, CloudResource, SecurityFinding

# ─── Risk Scoring Criteria ────────────────────────────────────────────────────
# Score range: 0.0 – 10.0
# Critical: 8.0 – 10.0 | High: 6.0 – 7.9 | Medium: 4.0 – 5.9
# Low: 2.0 – 3.9       | Info: 0.0 – 1.9

RULES = [
    {
        'id': 'CSA-001',
        'title': 'Public Storage Bucket',
        'description': 'Storage bucket is publicly accessible. Sensitive data may be exposed to unauthenticated internet users.',
        'applies_to': ['bucket'],
        'check': lambda r, c: r.is_public,
        'severity': 'critical',
        'score': 9.5,
        'remediation': 'Disable public access. Apply bucket policies restricting access to authorised principals only. Enable block-public-access settings.',
    },
    {
        'id': 'CSA-002',
        'title': 'Encryption Disabled',
        'description': 'Resource does not have encryption enabled. Data at rest may be exposed if the storage medium is compromised.',
        'applies_to': ['bucket', 'vm', 'database'],
        'check': lambda r, c: not r.encryption_enabled,
        'severity': 'high',
        'score': 7.5,
        'remediation': 'Enable server-side encryption using a managed or customer-managed key. Validate that all existing data is re-encrypted.',
    },
    {
        'id': 'CSA-003',
        'title': 'Logging Disabled',
        'description': 'Activity logging is not enabled. Security events and access activity cannot be audited.',
        'applies_to': ['bucket', 'vm', 'database', 'firewall'],
        'check': lambda r, c: not r.logging_enabled,
        'severity': 'medium',
        'score': 5.0,
        'remediation': 'Enable access and activity logging. Forward logs to a centralised, tamper-evident log store.',
    },
    {
        'id': 'CSA-004',
        'title': 'SSH Access Open to All IPs',
        'description': 'SSH port (22) is accessible from 0.0.0.0/0. This exposes the instance to brute-force and credential-stuffing attacks from the internet.',
        'applies_to': ['vm', 'firewall', 'security_group'],
        'check': lambda r, c: c.get('ssh_open_to_all', False),
        'severity': 'critical',
        'score': 9.0,
        'remediation': 'Restrict SSH access to trusted IP ranges. Use a bastion host or VPN. Consider key-based authentication only.',
    },
    {
        'id': 'CSA-005',
        'title': 'Versioning Disabled on Storage',
        'description': 'Object versioning is not enabled. Accidental or malicious deletions cannot be recovered.',
        'applies_to': ['bucket'],
        'check': lambda r, c: not c.get('versioning_enabled', True),
        'severity': 'low',
        'score': 3.0,
        'remediation': 'Enable versioning on the bucket. Configure lifecycle policies to manage version retention.',
    },
    {
        'id': 'CSA-006',
        'title': 'Overly Permissive IAM Policy',
        'description': 'IAM entity has wildcard (*) permissions or administrator-equivalent access that violates the principle of least privilege.',
        'applies_to': ['iam_user', 'iam_role'],
        'check': lambda r, c: c.get('wildcard_permissions', False),
        'severity': 'high',
        'score': 8.0,
        'remediation': 'Apply least-privilege permissions. Replace wildcard (*) actions with explicit action lists. Separate administrative and operational roles.',
    },
    {
        'id': 'CSA-007',
        'title': 'Publicly Accessible Virtual Machine',
        'description': 'Virtual machine has a public IP address and is directly accessible from the internet.',
        'applies_to': ['vm'],
        'check': lambda r, c: r.is_public,
        'severity': 'high',
        'score': 7.0,
        'remediation': 'Place the instance behind a load balancer or firewall. Remove the public IP if not required. Use private subnets.',
    },
    {
        'id': 'CSA-008',
        'title': 'Unrestricted Firewall Rule',
        'description': 'Firewall rule allows all inbound traffic (port range 0–65535 from 0.0.0.0/0).',
        'applies_to': ['firewall', 'security_group'],
        'check': lambda r, c: c.get('allow_all_inbound', False),
        'severity': 'critical',
        'score': 9.8,
        'remediation': 'Replace the allow-all rule with explicit rules permitting only required ports and source ranges. Deny all by default.',
    },
    {
        'id': 'CSA-009',
        'title': 'Database Publicly Accessible',
        'description': 'Database instance is configured with a public endpoint, making it reachable from the internet.',
        'applies_to': ['database'],
        'check': lambda r, c: r.is_public,
        'severity': 'critical',
        'score': 9.2,
        'remediation': 'Disable public accessibility. Place the database in a private subnet. Allow access only from application tier security groups.',
    },
    {
        'id': 'CSA-010',
        'title': 'No Access Restrictions on IAM Entity',
        'description': 'IAM user or role has no IP-based or MFA conditions on sensitive actions.',
        'applies_to': ['iam_user', 'iam_role'],
        'check': lambda r, c: not c.get('mfa_required', False),
        'severity': 'medium',
        'score': 5.5,
        'remediation': 'Enforce MFA for all IAM users with console access. Apply IP-condition policies for privileged roles.',
    },
]

SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def _load_config(resource: CloudResource) -> dict:
    try:
        return json.loads(resource.config_json or '{}')
    except Exception:
        return {}


def assess_resource(resource: CloudResource) -> list:
    """
    Run all applicable rules against a resource.
    Returns list of SecurityFinding objects (not yet committed).
    """
    config = _load_config(resource)
    findings = []

    for rule in RULES:
        if resource.resource_type not in rule['applies_to']:
            continue
        try:
            triggered = rule['check'](resource, config)
        except Exception:
            triggered = False

        if triggered:
            # Check if a finding for this rule+resource already exists (open)
            existing = SecurityFinding.query.filter_by(
                resource_id=resource.id,
                status='open'
            ).filter(
                SecurityFinding.finding_id.like(f"{rule['id']}%")
            ).first()

            if existing:
                continue  # Don't duplicate open findings

            finding = SecurityFinding(
                finding_id=f"{rule['id']}-{resource.resource_id}-{uuid.uuid4().hex[:8]}",
                resource_id=resource.id,
                title=rule['title'],
                description=rule['description'],
                severity=rule['severity'],
                risk_score=rule['score'],
                evidence=f"Configuration check: {rule['id']}",
                remediation=rule['remediation'],
                status='open',
                detected_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            findings.append(finding)

    return findings


def run_full_assessment() -> dict:
    """
    Assess all active resources. Returns summary dict.
    """
    resources = CloudResource.query.filter(
        CloudResource.status != 'deleted'
    ).all()

    total_new = 0
    total_resources = len(resources)

    for resource in resources:
        new_findings = assess_resource(resource)
        for f in new_findings:
            db.session.add(f)
            total_new += 1

        # Update resource risk score
        all_open = SecurityFinding.query.filter_by(
            resource_id=resource.id, status='open'
        ).all()
        if all_open:
            resource.risk_score = round(max(f.risk_score for f in all_open), 2)
        else:
            resource.risk_score = 0.0

    db.session.commit()

    return {
        'resources_scanned': total_resources,
        'new_findings': total_new,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


def severity_label(score: float) -> str:
    if score >= 8.0:
        return 'critical'
    if score >= 6.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    if score >= 2.0:
        return 'low'
    return 'info'
