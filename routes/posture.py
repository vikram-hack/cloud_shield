"""Security Posture routes"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import db, SecurityFinding, CloudResource
from modules.risk_assessment import run_full_assessment
from modules.audit_logger import log_action

posture_bp = Blueprint('posture', __name__, url_prefix='/posture')


@posture_bp.route('/')
@login_required
def overview():
    severity = request.args.get('severity', '')
    status = request.args.get('status', 'open')
    q = request.args.get('q', '').strip()

    query = SecurityFinding.query.join(CloudResource)
    if severity:
        query = query.filter(SecurityFinding.severity == severity)
    if status:
        query = query.filter(SecurityFinding.status == status)
    if q:
        query = query.filter(SecurityFinding.title.ilike(f'%{q}%'))

    findings = query.order_by(SecurityFinding.risk_score.desc()).all()

    # Stats
    from sqlalchemy import func
    sev_counts = db.session.query(
        SecurityFinding.severity, func.count(SecurityFinding.id)
    ).filter_by(status='open').group_by(SecurityFinding.severity).all()
    severity_stats = {s: c for s, c in sev_counts}

    return render_template('posture/overview.html',
                           findings=findings, severity_stats=severity_stats,
                           severity=severity, status=status, q=q)


@posture_bp.route('/run-assessment', methods=['POST'])
@login_required
def run_assessment():
    if not current_user.is_analyst():
        from flask import abort
        abort(403)
    result = run_full_assessment()
    log_action('assessment_run', result='success', metadata=result)
    flash(f"Assessment complete: {result['resources_scanned']} resources scanned, "
          f"{result['new_findings']} new finding(s).", 'success')
    return redirect(url_for('posture.overview'))


@posture_bp.route('/finding/<int:fid>/remediate', methods=['POST'])
@login_required
def remediate(fid):
    if not current_user.is_analyst():
        from flask import abort
        abort(403)
    finding = SecurityFinding.query.get_or_404(fid)
    finding.status = 'remediated'
    from datetime import datetime, timezone
    finding.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('finding_remediated', target_type='finding', target_id=finding.finding_id)
    flash(f'Finding "{finding.title}" marked as remediated.', 'success')
    return redirect(url_for('posture.overview'))


@posture_bp.route('/finding/<int:fid>/accept', methods=['POST'])
@login_required
def accept_risk(fid):
    if not current_user.is_analyst():
        from flask import abort
        abort(403)
    finding = SecurityFinding.query.get_or_404(fid)
    finding.status = 'accepted'
    from datetime import datetime, timezone
    finding.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action('finding_risk_accepted', target_type='finding', target_id=finding.finding_id)
    flash(f'Risk accepted for finding "{finding.title}".', 'info')
    return redirect(url_for('posture.overview'))
