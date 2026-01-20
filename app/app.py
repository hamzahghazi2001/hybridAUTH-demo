import os
import security
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

load_dotenv()

app = Flask(__name__)
# Secret key for encrypting session cookies
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, "database.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
# Create the login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.Text, nullable=False, unique=True)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    transports = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

class WebAuthnChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"ok": True})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug route to view all users and their credentials."""
    users = User.query.all()
    result = []
    for user in users:
        result.append({
            "id": user.id,
            "email": user.email,
            "created_at": user.created_at.isoformat(),
            "credentials_count": len(user.credentials),
            "credentials": [
                {
                    "id": cred.id,
                    "credential_id": cred.credential_id[:20] + "...",
                    "created_at": cred.created_at.isoformat(),
                    "transports": cred.transports
                } for cred in user.credentials
            ]
        })
    return jsonify(result)

@app.route("/register/start", methods=["POST"])
def register_start():
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    
    if not email:
        return jsonify({"error": "missing_email"}), 400
    
    # Basic email validation
    if "@" not in email or "." not in email:
        return jsonify({"error": "invalid_email"}), 400
    #query the database 
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()
    
    try:
        options_json = security.prepare_credential_creation(
            user=user,
            db=db,
            ChallengeModel=WebAuthnChallenge
        )
        return jsonify(options_json)
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/register/finish", methods=["POST"])
def register_finish():
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "missing_body"}), 400

    email = (payload.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "missing_email"}), 400

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"error": "unknown_user"}), 404

    try:
        result = security.verify_and_save_credential(
            user=user,
            registration_response=payload.get("credential"),
            db=db,
            ChallengeModel=WebAuthnChallenge,
            CredentialModel=Credential
        )

        if not result.get("ok"):
            return jsonify(result), 400

        return jsonify(result)
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e), "ok": False}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully.")
    app.run(debug=True)