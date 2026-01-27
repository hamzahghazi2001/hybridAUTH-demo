import secrets
import hashlib
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import session, redirect, url_for
from flask_login import login_required

def send_recovery_email(user_email, token):
    """
    Send recovery email with magic link
    """
    try:
        #Build the recovery URL
        recovery_url = f"http://localhost:5000/recover/email?token={token}&context=recovery"
        
        #Create email body
        email_body = f"""
Hello,

You requested a login link for your account.

Click here to log in:
{recovery_url}

This link is valid for 15 minutes and can only be used once.

If you didn't request this, ignore this email.

Thanks,
Your App Team
        """
        
        # Create email message
        msg = MIMEText(email_body)
        msg['Subject'] = 'Your Login Link'
        msg['From'] = 'noreply@yourapp.com'
        msg['To'] = user_email
        
        # Send via Mailpit (localhost:1025)
        with smtplib.SMTP('localhost', 1025) as server:
            server.send_message(msg)
        
        print(f"Email sent to {user_email}")
        return True
        
    except Exception as e:
        print(f" Error sending email: {e}")
        return False


def send_registration_email(user_email, token):
    """
    Send registration magic link to new user
    """
    try:
        # Build the registration URL 
        registration_url = f"http://localhost:5000/recover/email?token={token}&context=register"
        
        
        email_body = f"""
Hello,

Thanks for signing up! Click below to verify your email and create your passkey:

{registration_url}

This link is valid for 15 minutes and can only be used once.

If you didn't request this, ignore this email.

Thanks,
Your App Team
"""
        
        msg = MIMEText(email_body)
        msg['Subject'] = 'Verify Your Email - Complete Registration'
        msg['From'] = 'noreply@yourapp.com'
        msg['To'] = user_email
        
        with smtplib.SMTP('localhost', 1025) as server:
            server.send_message(msg)
        
        print(f"Registration email sent to {user_email}")
        return True
        
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# Decorator for recent auth requirement
def require_recent_auth(max_age_minutes=10):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            last_auth = session.get('last_auth_time')
            
            if not last_auth:
                return redirect(url_for('reauth'))
            
            last_auth_dt = datetime.fromisoformat(last_auth)
            age = datetime.now(timezone.utc) - last_auth_dt
            
            if age > timedelta(minutes=max_age_minutes):
                return redirect(url_for('reauth'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_backup_codes(db, BackupCode, user_id, count=5):
    """Generate new backup codes for a user."""
    BackupCode.query.filter_by(user_id=user_id).delete()
    plaintext_codes = []
    now = datetime.now(timezone.utc)
    
    for _ in range(count):
        raw_code = secrets.token_hex(4).upper()
        
        code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
        
        backup_code = BackupCode(
            user_id=user_id,
            code_hash=code_hash,
            created_at=now,
            used=False
        )
        db.session.add(backup_code)
        
        plaintext_codes.append(raw_code)
    
    db.session.commit()
    return plaintext_codes

def verify_backup_code(db, BackupCode, user_id, code):
    """Verify and consume a backup code."""
    input_code = code.strip(" ").upper()
    code_hash = hashlib.sha256(input_code.encode()).hexdigest()

    backup_code=BackupCode.query.filter_by(user_id=user_id, code_hash=code_hash, used=False).first()

    if not backup_code:  
        return False
    else:
        backup_code.used = True
        backup_code.used_at = datetime.now(timezone.utc)
        db.session.commit()
    return True