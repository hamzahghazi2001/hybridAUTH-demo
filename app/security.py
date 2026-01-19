import base64
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import webauthn
from flask import request


def _hostname():
    return str(urlparse(request.base_url).hostname)


def _origin():
    parsed = urlparse(request.base_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def prepare_credential_creation(user, db, ChallengeModel):
    """Generate WebAuthn registration options and store challenge."""
    options = webauthn.generate_registration_options(
        rp_id=_hostname(),
        rp_name="Hybrid-Auth Demo",
        user_id=str(user.id).encode('utf-8'),
        user_name=user.email,
        user_display_name=user.email.split('@')[0]
    )

    challenge = ChallengeModel(
        user_id=user.id,
        challenge=base64.b64encode(options.challenge).decode('utf-8'),
        type='registration',
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    db.session.add(challenge)
    db.session.commit()

    return json.loads(webauthn.options_to_json(options))


def verify_and_save_credential(user, registration_response, db, ChallengeModel, CredentialModel):
    """Verify registration response and save credential."""
    challenge_record = ChallengeModel.query.filter_by(
        user_id=user.id,
        type='registration',
        used_at=None
    ).filter(
        ChallengeModel.expires_at > datetime.now(timezone.utc)
    ).order_by(ChallengeModel.created_at.desc()).first()

    if not challenge_record:
        return {"ok": False, "error": "no_valid_challenge"}

    try:
        verification = webauthn.verify_registration_response(
            credential=registration_response,
            expected_challenge=base64.b64decode(challenge_record.challenge),
            expected_origin=_origin(),
            expected_rp_id=_hostname()
        )

        credential = CredentialModel(
            user_id=user.id,
            credential_id=base64.b64encode(verification.credential_id).decode('utf-8'),
            public_key=base64.b64encode(verification.credential_public_key).decode('utf-8'),
            sign_count=verification.sign_count,
            transports=','.join(registration_response.get('response', {}).get('transports', []))
        )

        challenge_record.used_at = datetime.now(timezone.utc)
        db.session.add(credential)
        db.session.commit()

        return {"ok": True, "message": "Passkey registered successfully"}

    except Exception as e:
        db.session.rollback()
        return {"ok": False, "error": "verification_failed", "details": str(e)}