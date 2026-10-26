"""
CloudShield Evidence Manager
"""
import os
import uuid
import hashlib
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from models import db, Evidence, EvidenceHandling
from modules.audit_logger import log_action

ALLOWED_EXTENSIONS = {'txt', 'log', 'csv', 'json', 'pdf'}


def _evidence_dir():
    from flask import current_app
    path = current_app.config['EVIDENCE_STORE_PATH']
    os.makedirs(path, exist_ok=True)
    return path


def _sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def store_evidence(file_stream, original_filename: str, evidence_type: str,
                   description: str, incident_id=None, collector=None,
                   is_demo=False) -> Evidence:
    """
    Save a file to the evidence store, calculate its SHA-256, and persist metadata.
    """
    safe_name = secure_filename(original_filename)
    ext = safe_name.rsplit('.', 1)[-1].lower() if '.' in safe_name else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f'File type .{ext} is not permitted in the evidence vault.')

    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    store_path = _evidence_dir()
    dest = os.path.join(store_path, stored_name)

    file_stream.save(dest)

    sha256 = _sha256(dest)
    size = os.path.getsize(dest)

    ev = Evidence(
        evidence_id=str(uuid.uuid4()),
        incident_id=incident_id,
        evidence_type=evidence_type,
        original_filename=safe_name,
        stored_filename=stored_name,
        collection_timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        collected_by=collector.id if collector else None,
        sha256_hash=sha256,
        file_size=size,
        description=description,
        integrity_status='verified',
        last_verified=datetime.now(timezone.utc).replace(tzinfo=None),
        is_demo=is_demo,
    )
    db.session.add(ev)
    db.session.flush()

    handling = EvidenceHandling(
        evidence_id=ev.id,
        action='collected',
        actor_id=collector.id if collector else None,
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        result='success',
        notes=f'Evidence collected and SHA-256 computed: {sha256}',
    )
    db.session.add(handling)
    db.session.commit()

    log_action('evidence_collected', target_type='evidence', target_id=ev.evidence_id,
               metadata={'filename': safe_name, 'sha256': sha256})

    return ev


def store_evidence_from_bytes(content: bytes, original_filename: str, evidence_type: str,
                               description: str, incident_id=None, collector=None,
                               is_demo=False) -> Evidence:
    """Save evidence from raw bytes (for programmatic use)."""
    safe_name = secure_filename(original_filename)
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    store_path = _evidence_dir()
    dest = os.path.join(store_path, stored_name)

    with open(dest, 'wb') as f:
        f.write(content)

    sha256 = _sha256(dest)
    size = os.path.getsize(dest)

    ev = Evidence(
        evidence_id=str(uuid.uuid4()),
        incident_id=incident_id,
        evidence_type=evidence_type,
        original_filename=safe_name,
        stored_filename=stored_name,
        collection_timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        collected_by=collector.id if collector else None,
        sha256_hash=sha256,
        file_size=size,
        description=description,
        integrity_status='verified',
        last_verified=datetime.now(timezone.utc).replace(tzinfo=None),
        is_demo=is_demo,
    )
    db.session.add(ev)
    db.session.flush()

    handling = EvidenceHandling(
        evidence_id=ev.id,
        action='collected',
        actor_id=collector.id if collector else None,
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        result='success',
        notes=f'Evidence collected programmatically. SHA-256: {sha256}',
    )
    db.session.add(handling)
    db.session.commit()

    log_action('evidence_collected', target_type='evidence', target_id=ev.evidence_id,
               metadata={'filename': safe_name, 'sha256': sha256})
    return ev


def verify_evidence(evidence_id_str: str, actor=None) -> dict:
    """
    Recalculate SHA-256 and compare with stored value.
    IMPORTANT: SHA-256 verifies content integrity relative to the recorded hash.
    It does not independently establish provenance or prove the complete chain of custody.
    """
    ev = Evidence.query.filter_by(evidence_id=evidence_id_str).first_or_404()
    store_path = _evidence_dir()
    dest = os.path.join(store_path, ev.stored_filename)

    if not os.path.isfile(dest):
        ev.integrity_status = 'missing'
        db.session.commit()
        return {'status': 'missing', 'message': 'Evidence file not found on disk.'}

    current_hash = _sha256(dest)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if current_hash == ev.sha256_hash:
        status = 'verified'
        message = 'SHA-256 hash matches recorded value. File content is unmodified.'
    else:
        status = 'tampered'
        message = (f'SHA-256 MISMATCH. Recorded: {ev.sha256_hash} | '
                   f'Current: {current_hash}. File may have been modified.')

    ev.integrity_status = status
    ev.last_verified = now

    handling = EvidenceHandling(
        evidence_id=ev.id,
        action='verified',
        actor_id=actor.id if actor else None,
        timestamp=now,
        result=status,
        notes=message,
    )
    db.session.add(handling)
    db.session.commit()

    log_action('evidence_verified', target_type='evidence', target_id=evidence_id_str,
               result=status, metadata={'sha256_match': status == 'verified'})

    return {'status': status, 'message': message, 'sha256': current_hash}


def get_evidence_file_path(evidence_id_str: str, actor=None) -> str:
    """Return the absolute path of evidence file after access logging."""
    ev = Evidence.query.filter_by(evidence_id=evidence_id_str).first_or_404()
    store_path = _evidence_dir()
    dest = os.path.join(store_path, ev.stored_filename)

    if not os.path.isfile(dest):
        raise FileNotFoundError('Evidence file not found.')

    handling = EvidenceHandling(
        evidence_id=ev.id,
        action='accessed',
        actor_id=actor.id if actor else None,
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        result='success',
    )
    db.session.add(handling)
    db.session.commit()

    return dest
