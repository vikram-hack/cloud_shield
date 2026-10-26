"""
Vercel Serverless Entrypoint for CloudShield
Wraps the Flask WSGI app for @vercel/python runtime.
"""
import os
import sys

# Add project root to Python path so imports resolve correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Vercel read-only filesystem workaround ─────────────────────────────────────
# Vercel's filesystem is read-only except for /tmp.
# Redirect SQLite DB and evidence store to /tmp when running on Vercel.
if os.environ.get("VERCEL"):
    os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/cloudshield.db")
    evidence_tmp = "/tmp/evidence_store"
    os.makedirs(evidence_tmp, exist_ok=True)

# ── Import & expose the Flask app ─────────────────────────────────────────────
from app import create_app

app = create_app("production")

# Vercel requires a top-level `app` object (WSGI callable)
