import os
import secrets
import security
import smtplib
import hashlib
from email.mime.text import MIMEText
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database setup
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "database.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean,nullable=True)

    def is_valid(self):
        """Check if token can still be used"""
        now = datetime.utcnow() 
        expires_at = self.expires_at.replace(tzinfo=None) if self.expires_at.tzinfo else self.expires_at
        
        if now <= expires_at and self.used != True:
            return True
        return False

def send_recovery_email(user_email, token):
    """
    Send recovery email with magic link
    """
    try:
        # Step 1: Build the recovery URL
        recovery_url = f"http://localhost:5000/recover?token={token}"
        
        # Step 2: Create email body
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
        
        # Step 3: Create email message
        msg = MIMEText(email_body)
        msg['Subject'] = 'Your Login Link'
        msg['From'] = 'noreply@yourapp.com'
        msg['To'] = user_email
        
        # Step 4: Send via Mailpit (localhost:1025)
        with smtplib.SMTP('localhost', 1025) as server:
            server.send_message(msg)
        
        print(f"Email sent to {user_email}")
        return True
        
    except Exception as e:
        print(f" Error sending email: {e}")
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

# Routes
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"ok": True})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', email=current_user.email)

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/reauth')
@login_required
def reauth():
    return render_template('reauth.html')

@app.route('/settings/change-email')
@require_recent_auth(max_age_minutes=10)
def change_email():
    return render_template('change_email.html')

@app.route('/recover-request', methods=['GET', 'POST'])
def recover_request():
    if request.method == 'GET':
        return render_template('recover_request.html')
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({"error": "Invalid email"}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        # Pretend message
        return jsonify({"ok": True, "message": "If account exists, email sent"})
    
    #Rate limiting check
    now = datetime.now(timezone.utc)
    previous_token = RecoveryToken.query.filter_by(
        user_id=user.id, 
        used=False
    ).order_by(RecoveryToken.created_at.desc()).first()

    if previous_token:
        db_created_at = previous_token.created_at
        if db_created_at.tzinfo is None:
            db_created_at = db_created_at.replace(tzinfo=timezone.utc)

        time_since_last = now - db_created_at
        
        if time_since_last < timedelta(minutes=5):
            seconds_elapsed = int(time_since_last.total_seconds())
            minutes_left = 5 - (seconds_elapsed // 60)
            return jsonify({
                "ok": False,
                "error": f"Too many requests. Please wait {minutes_left} more minute(s)."
            }), 429 
        else:
            RecoveryToken.query.filter_by(user_id=user.id, used=False).delete()
            db.session.commit()


    #Generate new token
    token_string = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token_string.encode()).hexdigest() 
    expires_at = now + timedelta(minutes=15) 

    recovery_token = RecoveryToken(
        user_id=user.id,
        token=token_hash, 
        created_at=now,
        expires_at=expires_at,
        used=False
    )
    db.session.add(recovery_token)
    db.session.commit()
    
    
    send_recovery_email(user.email, token_string) 
    return jsonify({
        "ok": True,
        "message": "If account exists, recovery link sent"
    })

@app.route('/recover')
def recover():
    """Process recovery link from email"""
        
    token_string = request.args.get('token')

    if not token_string:
        return "Invalid link", 400

    # Hash the incoming token to compare with stored hash
    token_hash = hashlib.sha256(token_string.encode()).hexdigest()
    token = RecoveryToken.query.filter_by(token=token_hash).first()

    if not token:
        return "Invalid or expired link", 400
    
    # Check if token is valid 
    if not token.is_valid():
        # Figure out WHY it's invalid
        if token.used:
            return "This link has already been used. Request a new one.", 400
        else:
            return "This link has expired. Request a new one.", 400
    
    #  Mark token as used 
    token.used = True
    db.session.commit()
    
    user = User.query.filter_by(id=token.user_id).first()
    
    # Log them User in 
    login_user(user, remember=True)
    session['last_auth_time'] = datetime.now(timezone.utc).isoformat()
    
    # Mark user MUST re-enroll
    session['needs_passkey_reregister'] = True

    # Redirect to dashboard
    return redirect(url_for('recover_reregister'))

@app.route('/recover/reregister')
@login_required
def recover_reregister():
    if not session.get('needs_passkey_reregister'):
        return redirect(url_for('dashboard'))

    return render_template('recover_reregister.html', email=current_user.email)

# Registration endpoints
@app.route("/register/start", methods=["POST"])
def register_start():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "invalid_email"}), 400

    is_reregister = bool(data.get("reregister", False))

    user = User.query.filter_by(email=email).first()

    if user and not is_reregister:
        return jsonify({"error": "Already a user"}), 400

    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()

    try:
        options = security.prepare_credential_creation(
            user=user,
            db=db,
            ChallengeModel=WebAuthnChallenge
        )
        return jsonify(options)
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/register/finish", methods=["POST"])
def register_finish():
    """Complete passkey registration."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    credential = data.get("credential")
    
    if not email or not credential:
        return jsonify({"error": "missing_data"}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    result = security.verify_and_save_credential(
        user=user,
        registration_response=credential,
        db=db,
        ChallengeModel=WebAuthnChallenge,
        CredentialModel=Credential
    )

    # clear the flag
    if result.get("ok"):
        data = request.get_json() or {}
        is_reregister = data.get('reregister', False)
        if is_reregister:
            session['needs_passkey_reregister'] = False

    return jsonify(result) if result.get("ok") else (jsonify(result), 400)

# Login endpoints
@app.route('/login/start', methods=['POST'])
def login_start():
    """Start passkey authentication process."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

    # Validate email
    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "invalid_email"}), 400

    # Check if user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if account is locked
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return jsonify({"error": "account_locked"}), 403

    # Check if user has credentials
    credentials = Credential.query.filter_by(user_id=user.id).all()
    if not credentials:
        return jsonify({"error": "no_credentials"}), 400

    try:
        options = security.prepare_authentication(
            user=user,
            credentials=credentials,
            db=db,
            ChallengeModel=WebAuthnChallenge
        )
        return jsonify(options)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login/finish', methods=['POST'])
def login_finish():
    """Complete passkey authentication."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    credential = data.get("credential")

    if not email or not credential:
        return jsonify({"error": "missing_data"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    # Verify the authentication
    result = security.verify_authentication(
        user=user,
        authentication_response=credential,
        db=db,
        ChallengeModel=WebAuthnChallenge,
        CredentialModel=Credential
    )

    if result.get("ok"):
        # Reset failed attempts and unlock account
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()

        # Log the user in
        login_user(user, remember=True)
        session['last_auth_time'] = datetime.now(timezone.utc).isoformat()
        
        return jsonify({"ok": True, "redirect": "/dashboard"})
    else:
        # Increment failed attempts
        user.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=60)
            db.session.commit()
            return jsonify({"ok": False, "error": "account_locked"}), 403
        
        db.session.commit()
        return jsonify({"ok": False, "error": result.get("error", "authentication_failed")}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        print("Database tables created successfully.")
    app.run(debug=True)