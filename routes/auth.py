"""Authentication routes"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from modules.audit_logger import log_action
from modules.attack_detection import record_failed_login, record_successful_login, inspect_request
from config import Config

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.overview'))

    if request.method == 'POST':
        # Check for attack patterns in form input (detection only, no execution)
        inspect_request()

        username = request.form.get('username', '').strip()[:64]
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))
        source_ip = request.remote_addr

        user = User.query.filter_by(username=username).first()

        # Account lockout check
        if user and user.is_locked and user.locked_until:
            if datetime.now(timezone.utc).replace(tzinfo=None) < user.locked_until:
                remaining = int((user.locked_until - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds() / 60)
                flash(f'Account locked due to repeated failures. Try again in {remaining} minute(s).', 'danger')
                log_action('login_blocked_lockout', target_type='user', target_id=username,
                           result='blocked', metadata={'ip': source_ip})
                return render_template('auth/login.html', username=username)

        if user and user.is_active and user.check_password(password):
            # Successful login
            user.failed_logins = 0
            user.is_locked = False
            user.locked_until = None
            user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
            db.session.commit()

            login_user(user, remember=remember)
            record_successful_login(user.id, user.username, source_ip)
            log_action('login_success', target_type='user', target_id=user.username,
                       result='success', metadata={'ip': source_ip})

            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard.overview'))
        else:
            # Failed login
            if user:
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= Config.MAX_LOGIN_ATTEMPTS:
                    user.is_locked = True
                    user.locked_until = (datetime.now(timezone.utc).replace(tzinfo=None) +
                                         timedelta(minutes=Config.LOGIN_LOCKOUT_MINUTES))
                db.session.commit()

            record_failed_login(username, source_ip)
            log_action('login_failure', target_type='user', target_id=username,
                       result='failure', metadata={'ip': source_ip})
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    log_action('logout', target_type='user', target_id=current_user.username, result='success')
    logout_user()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('auth.login'))
