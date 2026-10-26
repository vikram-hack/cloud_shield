"""Settings routes"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from models import db, User, DetectionRule
from modules.audit_logger import log_action

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


@settings_bp.route('/')
@login_required
def overview():
    if not current_user.is_admin():
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    rules = DetectionRule.query.order_by(DetectionRule.name).all()
    return render_template('settings/overview.html', users=users, rules=rules)


@settings_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin():
        abort(403)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()[:64]
        email = request.form.get('email', '').strip()[:120]
        password = request.form.get('password', '')
        role = request.form.get('role', 'viewer')

        if not username or not email or not password:
            flash('All fields required.', 'danger')
            return render_template('settings/create_user.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('settings/create_user.html')

        if len(password) < 12:
            flash('Password must be at least 12 characters.', 'danger')
            return render_template('settings/create_user.html')

        u = User(username=username, email=email, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        log_action('user_created', target_type='user', target_id=username,
                   metadata={'role': role})
        flash(f'User "{username}" created with role {role}.', 'success')
        return redirect(url_for('settings.overview'))

    return render_template('settings/create_user.html')


@settings_bp.route('/users/<int:uid>/toggle-lock', methods=['POST'])
@login_required
def toggle_lock(uid):
    if not current_user.is_admin():
        abort(403)
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash('Cannot lock your own account.', 'danger')
        return redirect(url_for('settings.overview'))
    user.is_locked = not user.is_locked
    if not user.is_locked:
        user.failed_logins = 0
        user.locked_until = None
    db.session.commit()
    log_action('user_lock_toggled', target_type='user', target_id=user.username,
               metadata={'locked': user.is_locked})
    flash(f'User "{user.username}" {"locked" if user.is_locked else "unlocked"}.', 'info')
    return redirect(url_for('settings.overview'))


@settings_bp.route('/users/<int:uid>/change-role', methods=['POST'])
@login_required
def change_role(uid):
    if not current_user.is_admin():
        abort(403)
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash('Cannot change your own role.', 'danger')
        return redirect(url_for('settings.overview'))
    new_role = request.form.get('role', 'viewer')
    old_role = user.role
    user.role = new_role
    db.session.commit()
    log_action('user_role_changed', target_type='user', target_id=user.username,
               metadata={'old_role': old_role, 'new_role': new_role})
    flash(f'Role changed to {new_role} for "{user.username}".', 'success')
    return redirect(url_for('settings.overview'))


@settings_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        current_password = request.form.get('current_password', '')
        if not current_user.check_password(current_password):
            flash('Current password incorrect.', 'danger')
            return render_template('settings/profile.html')
        if len(new_password) < 12:
            flash('New password must be at least 12 characters.', 'danger')
            return render_template('settings/profile.html')
        current_user.set_password(new_password)
        db.session.commit()
        log_action('password_changed', target_type='user', target_id=current_user.username)
        flash('Password updated successfully.', 'success')
    return render_template('settings/profile.html')


@settings_bp.route('/rules/<int:rid>/toggle', methods=['POST'])
@login_required
def toggle_rule(rid):
    if not current_user.is_admin():
        abort(403)
    rule = DetectionRule.query.get_or_404(rid)
    rule.is_enabled = not rule.is_enabled
    db.session.commit()
    log_action('detection_rule_toggled', target_type='rule', target_id=rule.name,
               metadata={'enabled': rule.is_enabled})
    flash(f'Rule "{rule.name}" {"enabled" if rule.is_enabled else "disabled"}.', 'info')
    return redirect(url_for('settings.overview'))
