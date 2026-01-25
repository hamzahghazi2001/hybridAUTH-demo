import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Credential, WebAuthnChallenge, RecoveryToken, BackupCode
import security
from helpers import require_recent_auth, send_recovery_email, generate_backup_codes, verify_backup_code

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

db.init_app(app) 

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
    return render_template('change_email.html',email=current_user.email)

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

@app.route('/recover/email')
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

@app.route('/login/backup', methods=['GET', 'POST'])
def login_backup():
    """Login using backup code"""
    if request.method == 'GET':
        return render_template('login_backup.html')
    
    data = request.get_json() or {}
    user = User.query.filter_by(email=email).first()
    code_hash = hashlib.sha256(input_code.encode()).hexdigest()
    backupcode = BackupCode.query.filter_by(code_hash=code_hash).first()
    now = datetime.utcnow() 
    if user.locked_until > now:
        return ("error": f"Account is locked unitil {user.locked_until}", 400)
    else:
        if backupcode:
            # Log them User in 
            login_user(user, remember=True)
            session['last_auth_time'] = datetime.now(timezone.utc).isoformat()
            backupcode.used=True
            backupcode.used_at = now
            db.session.commit()
        else:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=60)
            db.session.commit()
            
            if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                return jsonify({"error": "account_locked"}), 403
            
            return jsonify({"error": "invalid_credentials"}), 401

    # Mark user MUST re-enroll
    session['needs_passkey_reregister'] = True
    return redirect(url_for('recover_reregister'))

@app.route('/backup-codes/generate', methods=['POST'])
@login_required
@require_recent_auth(max_age_minutes=10)
def generate_backup_codes_route():
    codes = generate_backup_codes(db, BackupCode, current_user.id)
    return jsonify({
        "ok": True,
        "codes": codes,
        "message": "Save these codes securely. They won't be shown again."
    })

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