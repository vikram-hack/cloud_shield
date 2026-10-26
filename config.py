"""
CloudShield Configuration
"""
import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

# Detect Vercel serverless environment
_ON_VERCEL = bool(os.environ.get("VERCEL"))
_tmp_db   = "sqlite:////tmp/cloudshield.db"
_local_db = "sqlite:///" + os.path.join(basedir, "instance", "cloudshield.db")


class Config:
    # Security
    # IMPORTANT: Set SECRET_KEY as an environment variable in production / Vercel.
    # os.urandom() changes on every cold start → invalidates CSRF tokens.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'cs-dev-fallback-key-change-in-production-32x!'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Database – fall back to /tmp on Vercel (read-only root filesystem)
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get('DATABASE_URL') or
        (_tmp_db if _ON_VERCEL else _local_db)
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
    }

    # Session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_SECURE = _ON_VERCEL  # True on Vercel (HTTPS), False locally

    # Evidence store – writable /tmp directory on Vercel
    EVIDENCE_STORE_PATH = (
        '/tmp/evidence_store'
        if _ON_VERCEL else
        os.path.join(basedir, 'evidence_store')
    )

    # Application settings
    APP_NAME = 'CloudShield'
    APP_VERSION = '1.0.0'
    APP_ENV = 'LOCAL LAB'

    # Login security
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15

    # Pagination
    EVENTS_PER_PAGE = 25
    ALERTS_PER_PAGE = 25
    INCIDENTS_PER_PAGE = 20

    # Demo mode
    DEMO_MODE = True


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    EVIDENCE_STORE_PATH = os.path.join(basedir, 'instance', 'test_evidence')


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
