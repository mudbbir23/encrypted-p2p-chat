"""
WebAuthn / Passkey Manager.

Wraps the py_webauthn library with the application-specific RP configuration.
Handles registration and authentication challenge generation and verification.

Security notes:
- Challenges are 32 random bytes, stored in Redis with a 600-second TTL.
- Challenges are atomically GET+DEL'd from Redis — single-use guarantee.
- Signature counter (sign_count) is verified monotonically increasing to
  detect cloned authenticators (FIDO2 spec §14.1.1).
- The authenticator's public key is stored as a hex-encoded bytes object
  decoded from the CBOR/COSE credential.
"""
from __future__ import annotations

import secrets
from typing import Optional

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    parse_registration_credential_json,
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config import settings


class PasskeyManager:
    """
    Manages WebAuthn registration and authentication flows.

    RP settings are loaded from the application Settings object.
    Challenges are returned raw (bytes) so the caller can store them
    in Redis and include them in the returned options.
    """

    def __init__(self) -> None:
        self.rp_id = settings.RP_ID
        self.rp_name = settings.RP_NAME
        self.rp_origin = settings.RP_ORIGIN

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def generate_registration_options(
        self,
        user_id_bytes: bytes,
        username: str,
        display_name: str,
        existing_credential_ids: Optional[list[bytes]] = None,
    ) -> tuple[object, bytes]:
        """
        Generate WebAuthn registration options to send to the browser.

        Returns:
            (options, challenge_bytes)

        The challenge_bytes must be stored in Redis with a TTL by the caller.
        The client must send the challenge back during registration completion
        for verification.

        Configuration choices:
        - require_resident_key=True: Forces discoverable credentials (passkeys).
          This allows authentication without providing a username upfront.
        - user_verification=REQUIRED: Platform authenticators always verify the user
          (biometric or PIN). Security keys may require PIN as fallback.
        - attestation=NONE: We don't need to verify the authenticator model.
          Attestation verification adds significant complexity and is only required
          for enterprise environments where device models must be whitelisted.
        """
        challenge = secrets.token_bytes(settings.WEBAUTHN_CHALLENGE_BYTES)

        exclude_credentials = []
        if existing_credential_ids:
            exclude_credentials = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=cred_id,
                )
                for cred_id in existing_credential_ids
            ]

        authenticator_selection = AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id_bytes,
            user_name=username,
            user_display_name=display_name,
            challenge=challenge,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=authenticator_selection,
            exclude_credentials=exclude_credentials,
        )

        return options, challenge

    def verify_registration(
        self,
        credential: dict,
        challenge: bytes,
        require_user_verification: bool = True,
    ) -> object:
        """
        Verify a WebAuthn registration credential from the browser.

        Args:
            credential: The raw JSON object from navigator.credentials.create()
            challenge: The original challenge bytes (retrieved from Redis)
            require_user_verification: Ensure UV flag is set (biometric/PIN used)

        Returns:
            VerifiedRegistration object from py_webauthn

        Raises:
            InvalidCBORError, InvalidAuthenticatorDataStructure, or
            py_webauthn exceptions on verification failure.
        """
        reg_credential = parse_registration_credential_json(credential)

        verified = verify_registration_response(
            credential=reg_credential,
            expected_challenge=challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.rp_origin,
            require_user_verification=require_user_verification,
        )
        return verified

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    def generate_authentication_options(
        self,
        existing_credential_ids: Optional[list[bytes]] = None,
    ) -> tuple[object, bytes]:
        """
        Generate WebAuthn authentication options to send to the browser.

        Returns:
            (options, challenge_bytes)

        If existing_credential_ids is provided, the browser will only use
        those specific credentials. If empty, any registered credential works
        (conditional mediation / passkey discovery).
        """
        challenge = secrets.token_bytes(settings.WEBAUTHN_CHALLENGE_BYTES)

        allow_credentials = []
        if existing_credential_ids:
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=cred_id,
                )
                for cred_id in existing_credential_ids
            ]

        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        return options, challenge

    def verify_authentication(
        self,
        credential: dict,
        challenge: bytes,
        stored_public_key: bytes,
        stored_sign_count: int,
        require_user_verification: bool = True,
    ) -> tuple[object, int]:
        """
        Verify a WebAuthn authentication credential.

        Args:
            credential: Raw JSON object from navigator.credentials.get()
            challenge: Original challenge bytes from Redis
            stored_public_key: CBOR-encoded public key from registration record
            stored_sign_count: Counter stored from previous authentication
            require_user_verification: Enforce UV flag

        Returns:
            (VerifiedAuthentication, new_sign_count)

        Raises:
            ValueError: If sign_count indicates a cloned authenticator.
            py_webauthn exceptions on verification failure.
        """
        auth_credential = parse_authentication_credential_json(credential)

        verified = verify_authentication_response(
            credential=auth_credential,
            expected_challenge=challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.rp_origin,
            credential_public_key=stored_public_key,
            credential_current_sign_count=stored_sign_count,
            require_user_verification=require_user_verification,
        )

        # Clone detection: new counter MUST be greater than stored counter.
        # Exception: authenticators that return 0 must always return 0.
        new_sign_count = verified.new_sign_count
        if stored_sign_count > 0 and new_sign_count <= stored_sign_count:
            raise ValueError(
                f"Authenticator clone detected: new sign_count ({new_sign_count}) "
                f"is not greater than stored ({stored_sign_count}). "
                "Authentication rejected."
            )

        return verified, new_sign_count


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

passkey_manager = PasskeyManager()
