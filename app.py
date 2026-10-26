"""
CloudShield – Main Flask Application
MSc Information Security and Digital Forensics Platform
"""
import os
import uuid
import json
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (Flask, render_template, redirect, url_for, flash, request,
                   jsonify, abort, send_file, session)
from flask_login import (LoginManager, login_user, logout_user, login_required,
                         current_user)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
import io

from config import config
from models import (db, User, CloudResource, SecurityFinding, SecurityEvent,
                    Alert, Incident, IncidentNote, Evidence, EvidenceHandling,
                    ResponseAction, AuditLog, DetectionRule)

# ─── App Factory ──────────────────────────────────────────────────────────────

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure writable directories exist
    # On Vercel the root FS is read-only; evidence_store is already /tmp by config.
    if not os.environ.get("VERCEL"):
        os.makedirs(os.path.join(app.root_path, 'instance'), exist_ok=True)
    os.makedirs(app.config['EVIDENCE_STORE_PATH'], exist_ok=True)

    db.init_app(app)
    csrf = CSRFProtect(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access CloudShield.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        _ensure_default_users()

    # ─── Blueprints ───────────────────────────────────────────────────────────
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.resources import resources_bp
    from routes.posture import posture_bp
    from routes.events import events_bp
    from routes.alerts import alerts_bp
    from routes.incidents import incidents_bp
    from routes.forensics import forensics_bp
    from routes.evidence import evidence_bp
    from routes.reports import reports_bp
    from routes.audit import audit_bp
    from routes.settings import settings_bp
    from routes.response import response_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(resources_bp)
    app.register_blueprint(posture_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(forensics_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(response_bp)

    # ─── Context Processors ───────────────────────────────────────────────────
    @app.context_processor
    def inject_globals():
        open_alerts = 0
        if current_user and current_user.is_authenticated:
            open_alerts = Alert.query.filter(Alert.status.in_(['new', 'acknowledged'])).count()
        return {
            'app_name': app.config['APP_NAME'],
            'app_env': app.config['APP_ENV'],
            'open_alerts_count': open_alerts,
            'now': datetime.now(timezone.utc),
        }

    # ─── Error Handlers ───────────────────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.overview'))
        return redirect(url_for('auth.login'))

    return app


def _ensure_default_users():
    """Create default admin and analyst accounts on first run."""
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@cloudshield.local',
            role='admin',
        )
        admin.set_password('CloudShield@Admin2024!')
        db.session.add(admin)
        print('[INIT] Default admin created: admin / CloudShield@Admin2024!')

    if not User.query.filter_by(username='analyst_demo').first():
        analyst = User(
            username='analyst_demo',
            email='analyst@cloudshield.local',
            role='analyst',
        )
        analyst.set_password('Demo@Analyst2024!')
        db.session.add(analyst)
        print('[INIT] Demo analyst created: analyst_demo / Demo@Analyst2024!')

    if not User.query.filter_by(username='viewer_demo').first():
        viewer = User(
            username='viewer_demo',
            email='viewer@cloudshield.local',
            role='viewer',
        )
        viewer.set_password('Demo@Viewer2024!')
        db.session.add(viewer)
        print('[INIT] Demo viewer created: viewer_demo / Demo@Viewer2024!')

    db.session.commit()

    print('[INIT] CHANGE THIS PASSWORD IMMEDIATELY after first login.')


# ─── Permission Decorators ────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            from modules.attack_detection import record_unauthorized_access
            record_unauthorized_access(request.path, request.remote_addr,
                                       current_user.id if current_user.is_authenticated else None,
                                       current_user.username if current_user.is_authenticated else None)
            abort(403)
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_analyst():
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─── Entry Point ──────────────────────────────────────────────────────────────

app = create_app()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'seed':
        from modules.demo_data import seed_demo_data
        seed_demo_data(app)
    else:
        app.run(debug=True, host='127.0.0.1', port=5000)
