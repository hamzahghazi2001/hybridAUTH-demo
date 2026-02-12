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

def test_T03_expired_token_rejected(client):
    user = make_user()
    # make an expired token 
    raw_token= make_token(user.id, expired=True)
    recovery_url = f"/recover/email?token={raw_token}&context=recovery"

    response = client.get(recovery_url)
    assert response.status_code == 400 , f"Expected 400, got {response.status_code}"

def test_T04_old_token_deleted_when_new_created(client):
    """
        Testing that the real route deletes old tokens
        when issuing a new one
    """
    user = make_user()
    old_raw = secrets.token_urlsafe(32)
    old_hash = hashlib.sha256(old_raw.encode()).hexdigest()
    token_obj = RecoveryToken(                                
        user_id=user.id,
        token=old_hash,
        created_at=datetime.now(timezone.utc) - timedelta(minutes=6),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=9),
        used=False
    )
    db.session.add(token_obj)         
    db.session.commit()

    old_token = RecoveryToken.query.filter_by(token=old_hash).first()
    assert old_token is not None

    
    response = client.post('/login/email-request',
        json={"email": user.email, "context": "recovery"},
        content_type='application/json')
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Old token deleted
    check_old_token = RecoveryToken.query.filter_by(token=old_hash).first()
    assert check_old_token is None

    
    active_token = RecoveryToken.query.filter_by(user_id=user.id, used=False).count()
    assert active_token == 1, f"Expected 1 active token, got {active_token}"

def test_T05_lockout_after_five_failures(client):
    user = make_user()
    codes = make_backup_codes(user.id)

    # burn through 5 wrong attempts
    for i in range(5):
        client.post(
            '/login/backup-code',
            json={"email": user.email, "code": f"WRONG{i:04d}"},
            content_type='application/json'
        )

    # 6th attempt with VALID code should be locked
    r = client.post(
        '/login/backup-code',
        json={"email": user.email, "code": codes[0]},
        content_type='application/json'
    )

    assert r.status_code == 403, f"Error: expected 403, got {r.status_code}"
    assert r.get_json().get('error') == 'account_locked', (
        f"Error: expected 'account_locked', got {r.get_json().get('error')}"
    )

    lock_logs = AuditLog.query.filter_by(event_type='account_locked').all()
    assert len(lock_logs) >= 1, "Error: expected at least 1 account_locked log"

def test_T06_stale_session_blocked(client):
    user = make_user()

    fake_login(client, user.id, minutes_ago=11)

    r = client.get('/settings', follow_redirects=False)

    assert r.status_code == 302, f"Expected 302, got {r.status_code}"
    assert '/reauth' in r.headers.get('Location', ''), "Not redirected to /reauth"

def test_T07_recent_session_allowed(client):
    user = make_user()

    fake_login(client, user.id, minutes_ago=5)

    r = client.get('/settings', follow_redirects=False)

    assert r.status_code == 200, f"Expected 200, got {r.status_code}"