import sys
import os
import hashlib
import secrets
import pytest
from datetime import datetime, timezone, timedelta

from app import app as flask_app
from app.models import db, User, RecoveryToken, BackupCode, AuditLog


@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SERVER_NAME'] = 'localhost'

    with flask_app.app_context():
        db.create_all()              # Create fresh tables
        yield flask_app.test_client() #fake browser
        db.session.remove()
        db.drop_all()               

def make_user():
    """Create a verified user in the database. Returns the user."""
    user = User(
        email='testuser@example.com',
        email_verified=True,
        failed_login_attempts=0,
        locked_until=None
    )
    db.session.add(user)
    db.session.commit()
    return user

def make_token(user_id, expired=False):
    """
    Create a recovery token for a user. Returns the raw token string.
    If expired=True, the token is already past its TTL.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    if expired:
        created = datetime.now(timezone.utc) - timedelta(minutes=20)
        expires = created + timedelta(minutes=15)  # Expired 5 min ago
    else:
        created = datetime.now(timezone.utc)
        expires = created + timedelta(minutes=15)  # Valid for 15 min

    token = RecoveryToken(
        user_id=user_id,
        token=token_hash,
        created_at=created,
        expires_at=expires,
        used=False
    )
    db.session.add(token)
    db.session.commit()
    return raw_token

def make_backup_codes(user_id, count=5):
    """Create backup codes for a user, Returns list of raw code strings"""
    raw_codes = []
    for _ in range(count):
        raw_code = secrets.token_hex(4).upper()  
        code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
        bc = BackupCode(user_id=user_id, code_hash=code_hash, used=False)
        db.session.add(bc)
        raw_codes.append(raw_code)
    db.session.commit()
    return raw_codes


def fake_login(client, user_id, minutes_ago=0):
    """Pretend a user is logged in"""
    auth_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True
        sess['last_auth_time'] = auth_time.isoformat()


def make_token(user_id, expired=False):
    """
    Create a recovery token for a user. Returns the raw token string.
    If expired=True, the token is already past its TTL.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    if expired:
        created = datetime.now(timezone.utc) - timedelta(minutes=20)
        expires = created + timedelta(minutes=15)  # Expired 5 min ago
    else:
        created = datetime.now(timezone.utc)
        expires = created + timedelta(minutes=15)  # Valid for 15 min

    token = RecoveryToken(
        user_id=user_id,
        token=token_hash,
        created_at=created,
        expires_at=expires,
        used=False
    )
    db.session.add(token)
    db.session.commit()
    return raw_token

def make_backup_codes(user_id, count=5):
    """Create backup codes for a user, Returns list of raw code strings"""
    raw_codes = []
    for _ in range(count):
        raw_code = secrets.token_hex(4).upper()  
        code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
        bc = BackupCode(user_id=user_id, code_hash=code_hash, used=False)
        db.session.add(bc)
        raw_codes.append(raw_code)
    db.session.commit()
    return raw_codes


def fake_login(client, user_id, minutes_ago=0):
    """Pretend a user is logged in"""
    auth_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True
        sess['last_auth_time'] = auth_time.isoformat()

def test_health_check(client):
    response = client.get('/health')
    assert response.status_code == 200