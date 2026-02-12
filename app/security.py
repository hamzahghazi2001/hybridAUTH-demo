import base64
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import webauthn
from flask import request


def _hostname():
    """Extract hostname from request."""
    return str(urlparse(request.base_url).hostname)


def _origin():
    """Extract origin from request."""
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
    # Get the most recent unused registration challenge
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
        # Verify the registration response
        verification = webauthn.verify_registration_response(
            credential=registration_response,
            expected_challenge=base64.b64decode(challenge_record.challenge),
            expected_origin=_origin(),
            expected_rp_id=_hostname()
        )

        #stored ID matches what we get back during authentication
        credential = CredentialModel(
            user_id=user.id,
            credential_id=registration_response.get('id'),  # Store the base64url-encoded ID directly
            public_key=base64.b64encode(verification.credential_public_key).decode('utf-8'),
            sign_count=verification.sign_count,
            transports=','.join(registration_response.get('response', {}).get('transports', []))
        )

        # challenge makred as used
        challenge_record.used_at = datetime.now(timezone.utc)
        db.session.add(credential)
        db.session.commit()

        return {"ok": True, "message": "Passkey registered successfully"}

    except Exception as e:
        db.session.rollback()
        return {"ok": False, "error": "verification_failed", "details": str(e)}


def prepare_authentication(user, credentials, db, ChallengeModel):
    """Generate WebAuthn authentication options and store challenge."""
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    
    # list of allowed credentials
    allowed_creds = []
    for cred in credentials:
        try:
            # decode it for the WebAuthn library
            cred_id = base64.urlsafe_b64decode(cred.credential_id + '==')
            allowed_creds.append(PublicKeyCredentialDescriptor(id=cred_id))
        except Exception:
            continue  

    # Generate authentication options
    options = webauthn.generate_authentication_options(
        rp_id=_hostname(),
        allow_credentials=allowed_creds
    )

    # Store the challenge
    challenge = ChallengeModel(
        user_id=user.id,
        challenge=base64.b64encode(options.challenge).decode('utf-8'),
        type='authentication',
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    db.session.add(challenge)
    db.session.commit()

    return json.loads(webauthn.options_to_json(options))


def verify_authentication(user, authentication_response, db, ChallengeModel, CredentialModel):
    """Verify WebAuthn authentication response."""
    # Get the most recent unused authentication challenge
    challenge_record = ChallengeModel.query.filter_by(
        user_id=user.id,
        type='authentication',
        used_at=None
    ).filter(
        ChallengeModel.expires_at > datetime.now(timezone.utc)
    ).order_by(ChallengeModel.created_at.desc()).first()

    if not challenge_record:
        return {"ok": False, "error": "no_valid_challenge"}
    
    # Get the credential ID from the authentication response
    response_credential_id = authentication_response.get('id')
    
    if not response_credential_id:
        return {"ok": False, "error": "missing_credential_id"}
    
    # Find the matching credential
    credential = CredentialModel.query.filter_by(
        user_id=user.id,
        credential_id=response_credential_id
    ).first()
    
    if not credential:
        return {"ok": False, "error": "credential_not_found"}

    try:
        # Verify the authentication response
        verification = webauthn.verify_authentication_response(
            credential=authentication_response,
            expected_challenge=base64.b64decode(challenge_record.challenge),
            expected_origin=_origin(),
            expected_rp_id=_hostname(),
            credential_public_key=base64.b64decode(credential.public_key),
            credential_current_sign_count=credential.sign_count
        )
        
        # Update sign count and mark challenge as used
        credential.sign_count = verification.new_sign_count
        challenge_record.used_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return {"ok": True, "message": "Authentication successful"}
    
    except Exception as e:
        db.session.rollback()
        return {"ok": False, "error": "verification_failed", "details": str(e)}