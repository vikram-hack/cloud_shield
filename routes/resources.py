"""Cloud Resources routes"""
import uuid, json
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import login_required, current_user
from models import db, CloudResource, SecurityFinding
from modules.audit_logger import log_action
from modules.risk_assessment import assess_resource

resources_bp = Blueprint('resources', __name__, url_prefix='/resources')

RESOURCE_TYPES = ['vm', 'bucket', 'iam_user', 'iam_role', 'firewall', 'security_group', 'database']


@resources_bp.route('/')
@login_required
def list_resources():
    q = request.args.get('q', '').strip()
    rtype = request.args.get('type', '')
    status = request.args.get('status', '')

    query = CloudResource.query.filter(CloudResource.status != 'deleted')
    if q:
        query = query.filter(CloudResource.name.ilike(f'%{q}%'))
    if rtype:
        query = query.filter_by(resource_type=rtype)
    if status:
        query = query.filter_by(status=status)

    resources = query.order_by(CloudResource.risk_score.desc()).all()
    return render_template('resources/list.html', resources=resources,
                           resource_types=RESOURCE_TYPES, q=q, rtype=rtype, status=status)


@resources_bp.route('/<int:rid>')
@login_required
def detail(rid):
    resource = CloudResource.query.get_or_404(rid)
    config = {}
    try:
        config = json.loads(resource.config_json or '{}')
    except Exception:
        pass
    findings = SecurityFinding.query.filter_by(resource_id=rid).order_by(
        SecurityFinding.detected_at.desc()).all()
    return render_template('resources/detail.html', resource=resource,
                           config=config, findings=findings)


@resources_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if not current_user.is_analyst():
        abort(403)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()[:128]
        rtype = request.form.get('resource_type', '')
        owner = request.form.get('owner', '').strip()[:128]
        is_public = 'is_public' in request.form
        encryption = 'encryption_enabled' in request.form
        logging_e = 'logging_enabled' in request.form

        if not name or rtype not in RESOURCE_TYPES:
            flash('Name and valid resource type are required.', 'danger')
            return render_template('resources/form.html', resource_types=RESOURCE_TYPES)

        config_data = {}
        if rtype in ('vm', 'firewall', 'security_group'):
            config_data['ssh_open_to_all'] = 'ssh_open_to_all' in request.form
            config_data['allow_all_inbound'] = 'allow_all_inbound' in request.form
        if rtype == 'bucket':
            config_data['versioning_enabled'] = 'versioning_enabled' in request.form
        if rtype in ('iam_user', 'iam_role'):
            config_data['wildcard_permissions'] = 'wildcard_permissions' in request.form
            config_data['mfa_required'] = 'mfa_required' in request.form

        res = CloudResource(
            resource_id=f'res-{rtype[:3]}-{uuid.uuid4().hex[:6]}',
            name=name, resource_type=rtype, owner=owner,
            is_public=is_public, encryption_enabled=encryption,
            logging_enabled=logging_e, config_json=json.dumps(config_data),
            created_by=current_user.id,
        )
        db.session.add(res)
        db.session.flush()

        new_findings = assess_resource(res)
        for f in new_findings:
            db.session.add(f)
        if new_findings:
            res.risk_score = max(f.risk_score for f in new_findings)
        db.session.commit()

        log_action('resource_created', target_type='cloud_resource', target_id=res.resource_id,
                   metadata={'name': name, 'type': rtype})
        flash(f'Resource "{name}" created. {len(new_findings)} finding(s) detected.', 'success')
        return redirect(url_for('resources.detail', rid=res.id))

    return render_template('resources/form.html', resource_types=RESOURCE_TYPES)


@resources_bp.route('/<int:rid>/edit', methods=['GET', 'POST'])
@login_required
def edit(rid):
    if not current_user.is_analyst():
        abort(403)
    resource = CloudResource.query.get_or_404(rid)
    config = {}
    try:
        config = json.loads(resource.config_json or '{}')
    except Exception:
        pass

    if request.method == 'POST':
        resource.name = request.form.get('name', resource.name).strip()[:128]
        resource.owner = request.form.get('owner', '').strip()[:128]
        resource.is_public = 'is_public' in request.form
        resource.encryption_enabled = 'encryption_enabled' in request.form
        resource.logging_enabled = 'logging_enabled' in request.form
        resource.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

        new_config = config.copy()
        if resource.resource_type in ('vm', 'firewall', 'security_group'):
            new_config['ssh_open_to_all'] = 'ssh_open_to_all' in request.form
            new_config['allow_all_inbound'] = 'allow_all_inbound' in request.form
        if resource.resource_type == 'bucket':
            new_config['versioning_enabled'] = 'versioning_enabled' in request.form
        if resource.resource_type in ('iam_user', 'iam_role'):
            new_config['wildcard_permissions'] = 'wildcard_permissions' in request.form
            new_config['mfa_required'] = 'mfa_required' in request.form
        resource.config_json = json.dumps(new_config)

        db.session.commit()
        log_action('resource_updated', target_type='cloud_resource', target_id=resource.resource_id)
        flash('Resource updated.', 'success')
        return redirect(url_for('resources.detail', rid=resource.id))

    return render_template('resources/form.html', resource=resource,
                           resource_types=RESOURCE_TYPES, config=config)


@resources_bp.route('/<int:rid>/delete', methods=['POST'])
@login_required
def delete(rid):
    if not current_user.is_admin():
        abort(403)
    resource = CloudResource.query.get_or_404(rid)
    resource.status = 'deleted'
    db.session.commit()
    log_action('resource_deleted', target_type='cloud_resource', target_id=resource.resource_id)
    flash(f'Resource "{resource.name}" has been marked as deleted.', 'success')
    return redirect(url_for('resources.list_resources'))


@resources_bp.route('/<int:rid>/rescan', methods=['POST'])
@login_required
def rescan(rid):
    if not current_user.is_analyst():
        abort(403)
    resource = CloudResource.query.get_or_404(rid)
    new_findings = assess_resource(resource)
    for f in new_findings:
        db.session.add(f)
    all_open = SecurityFinding.query.filter_by(resource_id=resource.id, status='open').all()
    resource.risk_score = max((f.risk_score for f in all_open), default=0.0)
    db.session.commit()
    log_action('resource_rescanned', target_type='cloud_resource', target_id=resource.resource_id,
               metadata={'new_findings': len(new_findings)})
    flash(f'Rescan complete. {len(new_findings)} new finding(s).', 'success' if not new_findings else 'warning')
    return redirect(url_for('resources.detail', rid=resource.id))
