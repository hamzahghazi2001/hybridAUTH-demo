import sys
import os
import hashlib
import secrets
import pytest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app as flask_app
from models import db, User, RecoveryToken, BackupCode, AuditLog


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
