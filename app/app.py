import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session, redirect, url_for, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Credential, WebAuthnChallenge, RecoveryToken, BackupCode,AuditLog
import security
from helpers import require_recent_auth, send_recovery_email, generate_backup_codes, verify_backup_code,send_registration_email,log_event

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a3f2b9c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.after_request
def add_no_cache_headers(response):
    # Prevent showing cached authenticated pages after logout
    if current_user.is_authenticated:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

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
    response = redirect(url_for('index'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.delete_cookie("remember_token")         

    return response

@app.route('/reauth')
@login_required
def reauth():
    return render_template('reauth.html')

@app.route('/settings')
@login_required
@require_recent_auth(max_age_minutes=10)
def settings():
    return render_template('settings.html',email=current_user.email)

@app.route('/settings/change-email')
@login_required
@require_recent_auth(max_age_minutes=10)
def change_Code():
    return render_template('change_email.html',email=current_user.email)

@app.route('/settings/backup-code')
@login_required
@require_recent_auth(max_age_minutes=10)
def change_email():
    return render_template('genbackup.html')

@app.route('/login/email-request', methods=['GET', 'POST'])
def recover_request():
    if request.method == 'GET':
        return render_template('login_email.html')
    
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    context = data.get('context', 'recovery')
    
    if not email or '@' not in email:
        return jsonify({"error": "Invalid email"}), 400
    
    user = User.query.filter_by(email=email).first()
    
    # REGISTRATION CONTEXT
    if context == 'register':
        if user and user.email_verified:
            return jsonify({"error": "Account exists. Please login."}), 400
        
        # Create user if doesn't exist
        if not user:
            user = User(email=email, email_verified=False)
            db.session.add(user)
            db.session.commit()
    
    # RECOVERY CONTEXT
    else:
        if not user:
            # Pretend message
            return jsonify({"ok": True, "message": "If account exists, email sent"})
    
    # Rate limiting check
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
            seconds_elapsed  = int(time_since_last.total_seconds())
            minutes_left = 5 - (seconds_elapsed // 60)
            log_event("recovery_rate_limited", user_id=user.id, 
            details=f"retry_after={minutes_left}min", success=False) #Event loged for rate limit
            return jsonify({
                "ok": False,
                "error": f"Too many requests. Please wait {minutes_left} more minute(s)."
            }), 429
        else:
            RecoveryToken.query.filter_by(user_id=user.id, used=False).delete()
            db.session.commit()
    
    # Generate new token
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
    #adding a log event to the db for issuing recovery
    log_event("recovery_token_issued", user_id=user.id, details=f"context={context}")
    db.session.commit()
    
    # Send different emails based on email_verified
    if user.email_verified:
        send_recovery_email(user.email, token_string)
        message = "If account exists, recovery link sent"
    else:
        send_registration_email(user.email, token_string)
        message = "Verification email sent. Check your inbox to complete registration."
    
    return jsonify({"ok": True, "message": message})


@app.route('/recover/email')
def recover():
    """Process links from email"""
        
    token_string = request.args.get('token')

    if not token_string:
        return "Invalid link", 400

    # Hash the incoming token to compare with stored hash
    token_hash = hashlib.sha256(token_string.encode()).hexdigest()
    token = RecoveryToken.query.filter_by(token=token_hash).first()

    # Event log for failed recovery token
    log_event("recovery_token_failed", details="token_not_found", success=False)
    if not token:
        return "Invalid or expired link", 400
    
    # Check if token is valid 

    if not token.is_valid():
        # Event log for failed used or epxired token
        reason = "already_used" if token.used else "expired"
        log_event("recovery_token_failed", user_id=token.user_id,
                  details=f"token_id={token.id}, reason={reason}", success=False)
        
        if token.used:
            return "This link has already been used. Request a new one.", 400
        else:
            return "This link has expired. Request a new one.", 400
    
    #  Mark token as used 
    token.used = True
    db.session.commit()
    #Event log for recovery token used
    log_event("recovery_token_redeemed", user_id=token.user_id, 
              details=f"token_id={token.id}")
 

    user = User.query.filter_by(id=token.user_id).first()
    
    user.email_verified = True
    db.session.commit()


    # Log them in
    login_user(user, remember=True)
    session['last_auth_time'] = datetime.now(timezone.utc).isoformat()
    log_event("passkey_login_success", user_id=user.id)

    # Mark user needs passkey
    session['needs_passkey_reregister'] = True

    # Get context from URL
    context = request.args.get('context', 'recovery')

    # Redirect based on context
    if context == 'register':
        return redirect(url_for('register_success'))
    else:
        return redirect(url_for('recover_reregister'))

@app.route("/login/backup-code", methods=["GET", "POST"])
def login_backup():
    if request.method == "GET":
        return render_template("login_backup.html")

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "invalid_email"}), 400
    if not code:
        return jsonify({"error": "invalid_code"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "invalid_credentials"}), 401

    now = datetime.now(timezone.utc)

    locked_until = user.locked_until
    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)

    if locked_until and locked_until > now:
        return jsonify({"error": "account_locked", "locked_until": locked_until.isoformat()}), 403

    ok = verify_backup_code(db, BackupCode, user.id, code)

    if ok:
        user.failed_login_attempts = 0
        user.locked_until = None
        log_event("backup_code_login_success", user_id=user.id) # Event log for back up code success
        db.session.commit()

        login_user(user, remember=True)
        session["last_auth_time"] = now.isoformat()
        session["needs_passkey_reregister"] = True

        return jsonify({"ok": True, "redirect": url_for("recover_reregister")}), 200

    # failure
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    #Event log for failed back up code recovery attempt
    log_event("backup_code_login_failed", user_id=user.id,
        details=f"attempt={user.failed_login_attempts}/5", success=False)

    if user.failed_login_attempts >= 5:
        user.locked_until = now + timedelta(seconds=60)
        #Event log for account locked 
        log_event("account_locked", user_id=user.id,
            details=f"locked_until={user.locked_until.isoformat()}", success=False)

    db.session.commit()

    locked_until = user.locked_until
    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)

    if locked_until and locked_until > now:
        return jsonify({"error": "account_locked", "locked_until": locked_until.isoformat()}), 403

    return jsonify({"error": "invalid_credentials"}), 401

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/checkout')
@login_required
def checkout():
    return render_template('checkout.html', email=current_user.email)

@app.route('/checkout/complete', methods=['POST'])
@login_required
@require_recent_auth(max_age_minutes=10)
def checkout_complete():
    # Demo: just return success
    return jsonify({"ok": True, "message": "Order placed successfully!"})


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

@app.route('/register/success')
@login_required
def register_success():
    if not session.get('needs_passkey_reregister'):
        return redirect(url_for('dashboard'))
    return render_template('register_success.html', email=current_user.email)

# Registration endpoints
@app.route("/register/start", methods=["POST"])
def register_start():
    """Start passkey registration"""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    
    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "invalid_email"}), 400
    
    is_reregister = bool(data.get("reregister", False))
    user = User.query.filter_by(email=email).first()
    
    # Check email verification 
    if not is_reregister:
        if not user or not user.email_verified:
            return jsonify({"error": "email_not_verified"}), 403
    
    if user and not is_reregister:
        return jsonify({"error": "Already a user"}), 400
    
    # Only create user during re-registration
    if not user and is_reregister:
        user = User(email=email, email_verified=True)
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
        
        # Check if this is a re-authentication
        data = request.get_json() or {}
        is_reauth = data.get('is_reauth', False)
        
        if is_reauth:
            # Redirect back to protected page
            next_url = session.pop('next_url', '/dashboard')
            return jsonify({"ok": True, "redirect": next_url})
        else:
            # Normal login 
            return jsonify({"ok": True, "redirect": "/dashboard"})

    else:
        # Increment failed attempts
        user.failed_login_attempts += 1
        log_event("passkey_login_failed", user_id=user.id,
        details=f"attempt={user.failed_login_attempts}", success=False)

        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(seconds=60)
            db.session.commit()
            log_event("account_locked", user_id=user.id,
                details=f"locked_until={user.locked_until.isoformat()}", success=False)

            return jsonify({"ok": False, "error": "account_locked"}), 403
        
        db.session.commit()
        return jsonify({"ok": False, "error": result.get("error", "authentication_failed")}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        print("Database tables created successfully.")
    app.run(debug=True)