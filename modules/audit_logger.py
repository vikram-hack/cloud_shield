"""
CloudShield Audit Logger
"""
import json
from datetime import datetime, timezone
from flask import request
from models import db, AuditLog


def log_action(action, target_type=None, target_id=None, result='success',
               metadata=None, actor=None, actor_username=None):
    """Record a security-relevant action in the audit log."""
    from flask_login import current_user

    try:
        actor_id = None
        uname = actor_username or 'system'

        if actor:
            actor_id = actor.id
            uname = actor.username
        else:
            try:
                if current_user and current_user.is_authenticated:
                    actor_id = current_user.id
                    uname = current_user.username
            except Exception:
                pass

        source_ip = None
        try:
            source_ip = request.remote_addr
        except Exception:
            pass

        entry = AuditLog(
            timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
            actor_id=actor_id,
            actor_username=uname,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            result=result,
            metadata_json=json.dumps(metadata or {}),
            source_ip=source_ip,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        # Audit log failure must not crash application
        db.session.rollback()
        print(f'[AUDIT LOG ERROR] {exc}')
