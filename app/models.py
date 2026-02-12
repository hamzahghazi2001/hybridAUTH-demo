from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    credentials = db.relationship('Credential', backref='user', lazy=True, cascade='all, delete-orphan')
    challenges = db.relationship('WebAuthnChallenge', backref='user', lazy=True, cascade='all, delete-orphan')

    def is_active(self):
        if self.locked_until and self.locked_until > datetime.now(timezone.utc):
            return False
        return True

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.Text, nullable=False, unique=True)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    transports = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class WebAuthnChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RecoveryToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean,nullable=True)

    def is_valid(self):
        """Check if token can still be used"""
        now = datetime.now(timezone.utc)
        expires_at = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=timezone.utc)
        
        if now <= expires_at and self.used != True:
            return True
        return False
class BackupCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code_hash = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    used = db.Column(db.Boolean,nullable=True)
    used_at = db.Column(db.DateTime, nullable=True) 

    def is_active(self):
        return not self.used

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)#Extra context
    success = db.Column(db.Boolean, nullable=False, default=True)