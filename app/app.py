import os
import security
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
<<<<<<< HEAD
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
=======
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
>>>>>>> Login-logic

load_dotenv()

app = Flask(__name__)
<<<<<<< HEAD
=======
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database setup
>>>>>>> Login-logic
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "database.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

<<<<<<< HEAD
class User(db.Model):
=======
# Models
class User(db.Model, UserMixin):
>>>>>>> Login-logic
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class WebAuthnChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

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

# Registration endpoints
@app.route("/register/start", methods=["POST"])
def register_start():
    """Start passkey registration process."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    
    # Validate email
    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "invalid_email"}), 400
    
    # Get or create user
    user = User.query.filter_by(email=email).first()
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