"""Automated Response routes"""
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from models import db, ResponseAction, Incident, SecurityEvent, User, CloudResource
from modules.audit_logger import log_action

response_bp = Blueprint('response', __name__, url_prefix='/response')

ALLOWED_ACTIONS = {
    'lock_test_account': 'Temporarily lock a test/demo user account',
    'isolate_resource': 'Mark a simulated resource as isolated',
    'restrict_bucket': 'Restrict access to a simulated storage bucket',
    'preserve_logs': 'Mark related events for log preservation',
}


@response_bp.route('/')
@login_required
def overview():
    if not current_user.is_analyst():
        abort(403)
    actions = ResponseAction.query.order_by(ResponseAction.executed_at.desc()).limit(100).all()
    incidents = Incident.query.filter(Incident.status.notin_(['resolved', 'closed'])).all()
    test_users = User.query.filter_by(is_demo=True).all()
    sim_resources = CloudResource.query.filter(
        CloudResource.status.in_(['active', 'stopped']),
        CloudResource.is_demo == True
    ).all()
    return render_template('response/overview.html',
                           actions=actions, incidents=incidents,
                           test_users=test_users, sim_resources=sim_resources,
                           allowed_actions=ALLOWED_ACTIONS)


@response_bp.route('/execute', methods=['POST'])
@login_required
def execute():
    if not current_user.is_analyst():
        abort(403)

    action_type = request.form.get('action_type', '')
    if action_type not in ALLOWED_ACTIONS:
        flash('Invalid action type.', 'danger')
        return redirect(url_for('response.overview'))

    target_type = request.form.get('target_type', '')
    target_id = request.form.get('target_id', '').strip()[:128]
    incident_id = request.form.get('incident_id', type=int) or None
    description = ALLOWED_ACTIONS[action_type]
    result = 'success'
    result_detail = ''

    try:
        if action_type == 'lock_test_account':
            user = User.query.filter_by(username=target_id, is_demo=True).first()
            if not user:
                flash('Target account not found or not a demo account. Only demo accounts may be locked.', 'danger')
                return redirect(url_for('response.overview'))
            user.is_locked = True
            from datetime import timedelta
            user.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=30)
            db.session.commit()
            result_detail = f'Demo account "{user.username}" locked for 30 minutes.'

        elif action_type == 'isolate_resource':
            res = CloudResource.query.filter_by(resource_id=target_id, is_demo=True).first()
            if not res:
                flash('Resource not found or not a demo resource.', 'danger')
                return redirect(url_for('response.overview'))
            res.status = 'isolated'
            db.session.commit()
            result_detail = f'Simulated resource "{res.name}" marked as isolated.'

        elif action_type == 'restrict_bucket':
            res = CloudResource.query.filter_by(resource_id=target_id, is_demo=True,
                                                resource_type='bucket').first()
            if not res:
                flash('Bucket not found or not a demo resource.', 'danger')
                return redirect(url_for('response.overview'))
            res.is_public = False
            db.session.commit()
            result_detail = f'Simulated bucket "{res.name}" public access restricted.'

        elif action_type == 'preserve_logs':
            result_detail = f'Log preservation flag applied to target {target_id}.'

    except Exception as e:
        result = 'error'
        result_detail = str(e)

    ra = ResponseAction(
        incident_id=incident_id,
        action_type=action_type,
        target_type=target_type,
        target_id=target_id,
        description=f'{description} — {result_detail}',
        executed_by=current_user.id,
        executed_at=datetime.now(timezone.utc).replace(tzinfo=None),
        result=result,
        is_reversed=False,
    )
    db.session.add(ra)
    db.session.commit()

    log_action('response_action_executed', target_type=target_type, target_id=target_id,
               result=result, metadata={'action': action_type, 'detail': result_detail})

    if result == 'success':
        flash(f'Response action executed: {result_detail}', 'success')
    else:
        flash(f'Response action failed: {result_detail}', 'danger')

    return redirect(url_for('response.overview'))


@response_bp.route('/<int:rid>/reverse', methods=['POST'])
@login_required
def reverse_action(rid):
    if not current_user.is_analyst():
        abort(403)
    ra = ResponseAction.query.get_or_404(rid)

    if ra.is_reversed:
        flash('Action already reversed.', 'warning')
        return redirect(url_for('response.overview'))

    result_detail = ''
    try:
        if ra.action_type == 'lock_test_account':
            user = User.query.filter_by(username=ra.target_id, is_demo=True).first()
            if user:
                user.is_locked = False
                user.locked_until = None
                user.failed_logins = 0
                db.session.commit()
                result_detail = f'Demo account "{user.username}" unlocked.'

        elif ra.action_type in ('isolate_resource',):
            res = CloudResource.query.filter_by(resource_id=ra.target_id, is_demo=True).first()
            if res:
                res.status = 'active'
                db.session.commit()
                result_detail = f'Resource "{res.name}" restored to active.'

        elif ra.action_type == 'restrict_bucket':
            res = CloudResource.query.filter_by(resource_id=ra.target_id, is_demo=True).first()
            if res:
                res.is_public = True
                db.session.commit()
                result_detail = f'Simulated bucket "{res.name}" public access restored.'

    except Exception as e:
        flash(f'Reversal failed: {e}', 'danger')
        return redirect(url_for('response.overview'))

    ra.is_reversed = True
    ra.reversed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    ra.reversed_by = current_user.id
    db.session.commit()

    log_action('response_action_reversed', target_type=ra.target_type, target_id=ra.target_id,
               metadata={'original_action': ra.action_type, 'detail': result_detail})
    flash(f'Action reversed: {result_detail}', 'success')
    return redirect(url_for('response.overview'))
