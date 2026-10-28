"""Settings routes"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from models import db, User, DetectionRule
from modules.audit_logger import log_action

import re
from sqlalchemy import func

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

ALLOWED_ROLES = ('admin', 'analyst', 'viewer')


def validate_email_format(email: str) -> bool:
    """Validate email address format."""
    if not email or len(email) > 120:
        return False
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(pattern, email.strip()))


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password has minimum length, uppercase, lowercase, number, and special symbol."""
    if not password or len(password) < 10:
        return False, 'Password must be at least 10 characters long.'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase (capital) letter.'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number.'
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, 'Password must contain at least one special character or symbol (e.g. !@#$%^&*).'
    return True, ''


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
            flash('All fields are required.', 'danger')
            return render_template('settings/create_user.html', username=username, email=email, role=role)

        if not validate_email_format(email):
            flash('Please enter a valid email address (e.g. analyst@soc.cloudshield.local).', 'danger')
            return render_template('settings/create_user.html', username=username, email=email, role=role)

        if role not in ALLOWED_ROLES:
            flash(f'Invalid role. Allowed roles are: {", ".join(ALLOWED_ROLES)}.', 'danger')
            return render_template('settings/create_user.html', username=username, email=email, role=role)

        if User.query.filter(func.lower(User.username) == func.lower(username)).first():
            flash(f'Username "{username}" already exists. Please choose a different username.', 'danger')
            return render_template('settings/create_user.html', username=username, email=email, role=role)

        if User.query.filter(func.lower(User.email) == func.lower(email)).first():
            flash(f'Email address "{email}" is already registered.', 'danger')
            return render_template('settings/create_user.html', username=username, email=email, role=role)

        pw_ok, pw_msg = validate_password_strength(password)
        if not pw_ok:
            flash(pw_msg, 'danger')
            return render_template('settings/create_user.html', username=username, email=email, role=role)

        u = User(username=username, email=email, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        log_action('user_created', target_type='user', target_id=username,
                   metadata={'role': role, 'email': email})
        flash(f'User "{username}" successfully provisioned with role {role.upper()}.', 'success')
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
    if new_role not in ALLOWED_ROLES:
        flash(f'Invalid role. Allowed roles are: {", ".join(ALLOWED_ROLES)}.', 'danger')
        return redirect(url_for('settings.overview'))
    old_role = user.role
    user.role = new_role
    db.session.commit()
    log_action('user_role_changed', target_type='user', target_id=user.username,
               metadata={'old_role': old_role, 'new_role': new_role})
    flash(f'Role updated to {new_role.upper()} for "{user.username}".', 'success')
    return redirect(url_for('settings.overview'))


@settings_bp.route('/users/<int:uid>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(uid):
    """Admin route to alter an existing user account, email, role, and credentials."""
    if not current_user.is_admin():
        abort(403)
    user = User.query.get_or_404(uid)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()[:64]
        email = request.form.get('email', '').strip()[:120]
        role = request.form.get('role', user.role)
        new_password = request.form.get('password', '').strip()
        is_locked = 'is_locked' in request.form

        if not username or not email:
            flash('Username and email are required.', 'danger')
            return render_template('settings/edit_user.html', user=user)

        if not validate_email_format(email):
            flash('Please enter a valid email address (e.g. analyst@soc.cloudshield.local).', 'danger')
            return render_template('settings/edit_user.html', user=user)

        if role not in ALLOWED_ROLES:
            flash(f'Invalid role. Allowed roles are: {", ".join(ALLOWED_ROLES)}.', 'danger')
            return render_template('settings/edit_user.html', user=user)

        # Check unique username
        existing_u = User.query.filter(
            func.lower(User.username) == func.lower(username),
            User.id != user.id
        ).first()
        if existing_u:
            flash(f'Username "{username}" is already taken by another user.', 'danger')
            return render_template('settings/edit_user.html', user=user)

        # Check unique email
        existing_e = User.query.filter(
            func.lower(User.email) == func.lower(email),
            User.id != user.id
        ).first()
        if existing_e:
            flash(f'Email address "{email}" is already used by another account.', 'danger')
            return render_template('settings/edit_user.html', user=user)

        # Don't allow admin to demote or lock themselves
        if user.id == current_user.id:
            if role != 'admin':
                flash('You cannot demote your own administrator account.', 'danger')
                return render_template('settings/edit_user.html', user=user)
            if is_locked:
                flash('You cannot lock your own account.', 'danger')
                return render_template('settings/edit_user.html', user=user)

        # Optional password update
        if new_password:
            pw_ok, pw_msg = validate_password_strength(new_password)
            if not pw_ok:
                flash(pw_msg, 'danger')
                return render_template('settings/edit_user.html', user=user)
            user.set_password(new_password)
            user.failed_logins = 0

        old_role = user.role
        user.username = username
        user.email = email
        user.role = role
        user.is_locked = is_locked
        if not is_locked:
            user.failed_logins = 0
            user.locked_until = None

        db.session.commit()
        log_action('user_altered', target_type='user', target_id=user.username,
                   metadata={'old_role': old_role, 'new_role': role, 'email': email, 'locked': is_locked})
        flash(f'Account "{user.username}" successfully updated.', 'success')
        return redirect(url_for('settings.overview'))

    return render_template('settings/edit_user.html', user=user)


@settings_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        current_password = request.form.get('current_password', '')
        if not current_user.check_password(current_password):
            flash('Current password incorrect.', 'danger')
            return render_template('settings/profile.html')
        pw_ok, pw_msg = validate_password_strength(new_password)
        if not pw_ok:
            flash(pw_msg, 'danger')
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
