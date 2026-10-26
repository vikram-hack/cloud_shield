"""Audit Log routes"""
from flask import Blueprint, render_template, request, abort
from flask_login import login_required, current_user
from models import db, AuditLog

audit_bp = Blueprint('audit', __name__, url_prefix='/audit')


@audit_bp.route('/')
@login_required
def list_logs():
    if not current_user.is_admin():
        abort(403)

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    actor = request.args.get('actor', '').strip()
    action = request.args.get('action', '').strip()

    query = AuditLog.query
    if q:
        query = query.filter(AuditLog.action.ilike(f'%{q}%'))
    if actor:
        query = query.filter(AuditLog.actor_username.ilike(f'%{actor}%'))
    if action:
        query = query.filter_by(action=action)

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False)

    actions = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    actions = [a[0] for a in actions]

    return render_template('audit/list.html',
                           pagination=pagination, logs=pagination.items,
                           actions=actions, q=q, actor=actor, action=action)
