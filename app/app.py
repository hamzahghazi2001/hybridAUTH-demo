import os
from flask import Flask, jsonify, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-fallback')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db =SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    credentials = db.relationship('Credential', backref='user', lazy=True)
    challenges = db.relationship('WebAuthnChallenge', backref='user', lazy=True)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.Text, nullable=False)
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

@app.route('/health', methods=['GET'])
def health():
    health_data = {"ok": True}
    return jsonify(health_data)

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

if __name__ == '__main__':
        with app.app_context():
            db.create_all()
            print("Database tables created successfully.")
        app.run(debug=True)