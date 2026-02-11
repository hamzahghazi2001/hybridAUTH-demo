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


def fake_login(client, user_id, minutes_ago=0):
    """Pretend a user is logged in"""
    auth_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True
        sess['last_auth_time'] = auth_time.isoformat()

# def test_visit_recovery(client):
#     user =  make_user()
#     raw_token = make_token(user.id)
#     recovery_url =f"/recover/email?token={raw_token}&context=recovery"
#     response = client.get(recovery_url)
#     print(response.status_code)

# def test_assert_practice(client):
#     response = client.get('/health')
#     assert  response.status_code == 200,  f"Expected 200, got {response.status_code}"

# def test_audit_log_check(client):
#     user = make_user()
#     raw_token = make_token(user.id)
#     recovery_url =f"/recover/email?token={raw_token}&context=recovery"
#     response = client.get(recovery_url)
#     logs = AuditLog.query.filter_by(event_type='recovery_token_redeemed').all()
#     assert len(logs) ==1 , f"error"

# def test_submit_backup_code(client):
#     user = make_user()
#     codes = make_backup_codes(user.id)
#     code = codes[0]
#     response = client.post('/login/backup-code',
#     json={"email": user.email, "code": code},
#     content_type='application/json')
#     assert response.status_code == 200, f"Expected 200, got {response.status_code}"

def test_T01_magic_link_replay_blocked(client):
    user = make_user()
    raw_token = make_token(user.id)

    recovery_url = f"/recover/email?token={raw_token}&context=recovery"

    r1 = client.get(recovery_url, follow_redirects=False)
    assert r1.status_code in (200, 302), f"Expected 200 or 302, got {r1.status_code}"

    # replay same URL again
    r2 = client.get(recovery_url, follow_redirects=False)
    assert r2.status_code in (400, 410), f"Expected 400/410, got {r2.status_code}"

    fail_logs = AuditLog.query.filter_by(event_type="recovery_token_failed").all()
    assert len(fail_logs) >= 1, "error no logs"

def test_T02_backup_code_replay_blocked(client):
    user = make_user()
    codes = make_backup_codes(user.id)
    code = codes[0]
    r1 = client.post('/login/backup-code',
    json={"email": user.email, "code": code},
    content_type='application/json')
    assert r1.status_code == 200, f"Expected 200, got {r1.status_code}"

    # replay same code again
    r2 = client.post('/login/backup-code',
    json={"email": user.email, "code": code},
    content_type='application/json')
    assert r2.status_code == 401, f"Expected 401, got {r2.status_code}"