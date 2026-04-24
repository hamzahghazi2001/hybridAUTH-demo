# Hybrid Authentication System

Implementation for my BSc Honors dissertation (F20PA, Heriot-Watt University Dubai).

A passkey-first hybrid authentication system for e-commerce. Primary authentication uses WebAuthn passkeys; account recovery is handled via magic links and one-time backup codes. Sensitive actions require step-up re-authentication, and key events are written to an audit log.

This is academic research code, not for production use.

## Requirements

- Python 3.10 or newer
- [Mailpit](https://github.com/axllent/mailpit) running locally (captures emails sent during registration and recovery flows)
- A browser with WebAuthn support (Chrome, Edge, Firefox, Safari)

## Setup

```bash
git clone https://github.com/hamzahghazi2001/hybridAUTH-demo.git
cd hybridAUTH-demo
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
FLASK_DEBUG=True
SECRET_KEY=<any-random-string>
AUTH_SALT=<any-random-string>
DATABASE_URL=sqlite:///instance/database.db
WEBAUTHN_RP_NAME=Hybrid-Auth Demo
WEBAUTHN_CHALLENGE_TTL_SECONDS=600
```

Start Mailpit in a separate terminal. Web UI is at http://localhost:8025, SMTP on port 1025.

## Running the app

```bash
flask --app app run
```

App runs at http://localhost:5000. The SQLite database is created automatically on first run.

## Running the tests

```bash
pytest
```

## Trying the flows

1. Register a new account — the browser prompts for a passkey.
2. Log out and log back in using the passkey.
3. Trigger the recovery flow ("forgot passkey") — the magic link appears in Mailpit.
4. Attempt a sensitive action while logged in — the app prompts for step-up re-authentication.
5. Backup codes can be generated and used as an alternative recovery path.

## Project structure

```
app/           Flask application (routes, models, helpers, security)
tests/         Pytest suite
instance/      SQLite database (created at runtime)
```

WebAuthn requires either `localhost` or HTTPS.
