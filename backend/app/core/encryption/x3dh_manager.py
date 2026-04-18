"""
X3DH (Extended Triple Diffie-Hellman) Manager.

Implements the Signal Protocol X3DH key agreement for asynchronous
end-to-end encrypted messaging.

Reference: https://signal.org/docs/specifications/x3dh/

Security properties provided:
- Mutual authentication via identity keys (DH1 + DH2)
- Forward secrecy via ephemeral key (DH3)
- One-time prekey forward secrecy for initial message (DH4, optional)
- MITM protection via Ed25519 signature on signed prekey

CRITICAL: All random key generation uses os.urandom via cryptography library.
Never use random.random() or any non-CSPRNG source for key material.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import settings


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """A keypair with base64url-encoded public and private keys."""
    public_key_b64: str
    private_key_b64: str


@dataclass
class PreKeyBundle:
    """
    Public key material published by a user so others can initiate sessions.
    All fields are base64url-encoded byte strings.
    """
    user_id: str
    identity_key_x25519: str     # X25519 public key (DH operations)
    identity_key_ed25519: str    # Ed25519 public key (signature verification)
    signed_prekey: str           # X25519 public key (signed prekey)
    signed_prekey_signature: str # Ed25519 signature over signed_prekey bytes
    one_time_prekey: Optional[str] = None  # X25519 public key (consumed on use)
    one_time_prekey_id: Optional[int] = None


@dataclass
class X3DHResult:
    """
    Output of a successful X3DH exchange.
    """
    shared_key: bytes          # 32-byte shared secret (output of HKDF)
    associated_data: bytes     # IK_A_pub || IK_B_pub (for AES-GCM authentication)
    ephemeral_public_key: str  # Alice's ephemeral public key (base64url) — sent to Bob
    used_one_time_prekey: bool = False


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    """URL-safe base64 encoding without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(data: str) -> bytes:
    """URL-safe base64 decoding with missing padding tolerance."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _serialize_x25519_private(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_x25519_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _serialize_ed25519_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_ed25519_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _load_x25519_private(b64: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_b64_decode(b64))


def _load_x25519_public(b64: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(_b64_decode(b64))


def _load_ed25519_private(b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_b64_decode(b64))


def _load_ed25519_public(b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64_decode(b64))


# ---------------------------------------------------------------------------
# X3DH Manager
# ---------------------------------------------------------------------------

class X3DHManager:
    """
    Implements the X3DH key agreement protocol.

    All methods are pure functions that accept key material as arguments
    and return derived key material. No mutable state is stored.
    """

    # -----------------------------------------------------------------------
    # Key generation
    # -----------------------------------------------------------------------

    def generate_identity_keypair_x25519(self) -> KeyPair:
        """
        Generate an X25519 identity keypair for DH operations.
        The identity keypair is long-lived and should be generated once per user.
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair(
            public_key_b64=_b64_encode(_serialize_x25519_public(public_key)),
            private_key_b64=_b64_encode(_serialize_x25519_private(private_key)),
        )

    def generate_identity_keypair_ed25519(self) -> KeyPair:
        """
        Generate an Ed25519 identity keypair for digital signatures.
        Used to sign the signed prekey, proving it belongs to this identity.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair(
            public_key_b64=_b64_encode(_serialize_ed25519_public(public_key)),
            private_key_b64=_b64_encode(_serialize_ed25519_private(private_key)),
        )

    def generate_signed_prekey(
        self,
        identity_private_ed25519_b64: str,
    ) -> tuple[KeyPair, str]:
        """
        Generate a signed prekey (SPK) and sign it with the Ed25519 identity key.

        Returns:
            (signed_prekey_keypair, signature_b64)

        The SPK is an X25519 keypair. The Ed25519 signature over the SPK public key
        bytes allows receivers to verify the SPK was produced by the identity holder.

        This prevents MITM attacks where the server substitutes its own SPK.
        """
        # Generate fresh X25519 keypair for the signed prekey
        spk_private = X25519PrivateKey.generate()
        spk_public = spk_private.public_key()
        spk_public_bytes = _serialize_x25519_public(spk_public)

        # Sign the raw public key bytes with the Ed25519 identity key
        identity_private = _load_ed25519_private(identity_private_ed25519_b64)
        signature_bytes: bytes = identity_private.sign(spk_public_bytes)

        keypair = KeyPair(
            public_key_b64=_b64_encode(spk_public_bytes),
            private_key_b64=_b64_encode(_serialize_x25519_private(spk_private)),
        )
        return keypair, _b64_encode(signature_bytes)

    def generate_one_time_prekeys(self, count: int) -> list[KeyPair]:
        """
        Generate `count` one-time prekeys (OPKs).

        Each OPK is an X25519 keypair used in exactly one X3DH handshake.
        After use, the OPK is deleted — it is never reused.
        """
        if count <= 0 or count > 500:
            raise ValueError(f"OPK count must be between 1 and 500, got {count}")

        prekeys = []
        for _ in range(count):
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()
            prekeys.append(
                KeyPair(
                    public_key_b64=_b64_encode(_serialize_x25519_public(public_key)),
                    private_key_b64=_b64_encode(_serialize_x25519_private(private_key)),
                )
            )
        return prekeys

    # -----------------------------------------------------------------------
    # Signature verification
    # -----------------------------------------------------------------------

    def verify_signed_prekey(
        self,
        signed_prekey_b64: str,
        signature_b64: str,
        identity_public_ed25519_b64: str,
    ) -> bool:
        """
        Verify the Ed25519 signature on a signed prekey.

        MUST be called before performing X3DH. Failure to verify allows
        a MITM to substitute a server-controlled key.

        Returns True if valid, False if signature is invalid.
        """
        try:
            spk_public_bytes = _b64_decode(signed_prekey_b64)
            signature_bytes = _b64_decode(signature_b64)
            identity_public = _load_ed25519_public(identity_public_ed25519_b64)
            # Ed25519 verify raises InvalidSignature on failure
            identity_public.verify(signature_bytes, spk_public_bytes)
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

    # -----------------------------------------------------------------------
    # X3DH Key Exchange — Sender Side (Alice initiates)
    # -----------------------------------------------------------------------

    def perform_x3dh_sender(
        self,
        alice_identity_private_x25519_b64: str,
        alice_identity_public_x25519_b64: str,
        bob_bundle: PreKeyBundle,
    ) -> X3DHResult:
        """
        Perform the sender-side X3DH key agreement.

        Alice initiates a session with Bob using Bob's prekey bundle.

        Steps:
        1. Verify Bob's signed prekey signature (MANDATORY — aborts if invalid)
        2. Generate Alice's ephemeral keypair (EK_A)
        3. Compute DH1..DH4
        4. Derive SK via HKDF-SHA256
        5. Compute associated data = IK_A_pub || IK_B_pub

        Returns:
            X3DHResult containing the shared key, associated data, and Alice's
            ephemeral public key (which Bob needs to replicate the exchange).

        Raises:
            ValueError: If the signed prekey signature is invalid.
        """
        # --- Step 1: Verify Bob's signed prekey signature ---
        if not self.verify_signed_prekey(
            signed_prekey_b64=bob_bundle.signed_prekey,
            signature_b64=bob_bundle.signed_prekey_signature,
            identity_public_ed25519_b64=bob_bundle.identity_key_ed25519,
        ):
            raise ValueError(
                "Signed prekey signature verification failed. "
                "Possible MITM attack — aborting key exchange."
            )

        # --- Load Alice's identity key ---
        alice_ik_private = _load_x25519_private(alice_identity_private_x25519_b64)
        alice_ik_public_bytes = _b64_decode(alice_identity_public_x25519_b64)

        # --- Load Bob's public keys ---
        bob_ik_public = _load_x25519_public(bob_bundle.identity_key_x25519)
        bob_spk_public = _load_x25519_public(bob_bundle.signed_prekey)
        bob_ik_public_bytes = _b64_decode(bob_bundle.identity_key_x25519)

        # --- Step 2: Generate ephemeral keypair (EK_A) ---
        # This key is used once and the private component is NEVER stored.
        alice_ek_private = X25519PrivateKey.generate()
        alice_ek_public = alice_ek_private.public_key()
        alice_ek_public_bytes = _serialize_x25519_public(alice_ek_public)

        # --- Step 3: Compute DH operations ---
        # DH1 = X25519(IK_A_private, SPK_B) — authenticates Alice to Bob
        dh1 = alice_ik_private.exchange(bob_spk_public)
        # DH2 = X25519(EK_A_private, IK_B)  — authenticates Bob to Alice
        dh2 = alice_ek_private.exchange(bob_ik_public)
        # DH3 = X25519(EK_A_private, SPK_B) — ephemeral forward secrecy
        dh3 = alice_ek_private.exchange(bob_spk_public)

        key_material = dh1 + dh2 + dh3

        # DH4 = X25519(EK_A_private, OPK_B) — additional OPK forward secrecy (optional)
        used_opk = False
        if bob_bundle.one_time_prekey is not None:
            bob_opk_public = _load_x25519_public(bob_bundle.one_time_prekey)
            dh4 = alice_ek_private.exchange(bob_opk_public)
            key_material += dh4
            used_opk = True

        # --- Step 4: Derive shared key via HKDF-SHA256 ---
        # 0xFF * 32 prefix is specified by the X3DH standard as a domain separator.
        # It ensures the HKDF input is distinguishable from other protocols.
        f = b"\xff" * settings.X25519_KEY_SIZE
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=settings.HKDF_OUTPUT_SIZE,
            salt=b"\x00" * settings.X25519_KEY_SIZE,
            info=b"X3DH",
        )
        shared_key = hkdf.derive(f + key_material)

        # --- Step 5: Compute associated data ---
        # AD = IK_A_pub || IK_B_pub
        # This binds both identities to all subsequent AES-GCM operations.
        associated_data = alice_ik_public_bytes + bob_ik_public_bytes

        return X3DHResult(
            shared_key=shared_key,
            associated_data=associated_data,
            ephemeral_public_key=_b64_encode(alice_ek_public_bytes),
            used_one_time_prekey=used_opk,
        )

    # -----------------------------------------------------------------------
    # X3DH Key Exchange — Receiver Side (Bob responds)
    # -----------------------------------------------------------------------

    def perform_x3dh_receiver(
        self,
        bob_identity_private_x25519_b64: str,
        bob_identity_public_x25519_b64: str,
        bob_signed_prekey_private_b64: str,
        alice_ephemeral_public_b64: str,
        alice_identity_public_x25519_b64: str,
        bob_one_time_prekey_private_b64: Optional[str] = None,
    ) -> X3DHResult:
        """
        Perform the receiver-side X3DH key agreement.

        Bob replicates Alice's computation using his own private keys
        and the public information Alice sent (her ephemeral public key).

        The math is identical — Diffie-Hellman is symmetric:
            X25519(alice_priv, bob_pub) == X25519(bob_priv, alice_pub)

        Raises:
            ValueError: If required key arguments are missing or invalid.
        """
        # --- Load Bob's private keys ---
        bob_ik_private = _load_x25519_private(bob_identity_private_x25519_b64)
        bob_spk_private = _load_x25519_private(bob_signed_prekey_private_b64)
        bob_ik_public_bytes = _b64_decode(bob_identity_public_x25519_b64)

        # --- Load Alice's public keys ---
        alice_ik_public = _load_x25519_public(alice_identity_public_x25519_b64)
        alice_ek_public = _load_x25519_public(alice_ephemeral_public_b64)
        alice_ik_public_bytes = _b64_decode(alice_identity_public_x25519_b64)

        # --- Replicate DH operations (roles reversed, same result) ---
        # DH1 = X25519(SPK_B_private, IK_A_public)
        dh1 = bob_spk_private.exchange(alice_ik_public)
        # DH2 = X25519(IK_B_private, EK_A_public)
        dh2 = bob_ik_private.exchange(alice_ek_public)
        # DH3 = X25519(SPK_B_private, EK_A_public)
        dh3 = bob_spk_private.exchange(alice_ek_public)

        key_material = dh1 + dh2 + dh3

        # DH4 = X25519(OPK_B_private, EK_A_public) — only if OPK was used
        if bob_one_time_prekey_private_b64 is not None:
            bob_opk_private = _load_x25519_private(bob_one_time_prekey_private_b64)
            dh4 = bob_opk_private.exchange(alice_ek_public)
            key_material += dh4

        # --- Derive shared key via HKDF-SHA256 (identical to sender) ---
        f = b"\xff" * settings.X25519_KEY_SIZE
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=settings.HKDF_OUTPUT_SIZE,
            salt=b"\x00" * settings.X25519_KEY_SIZE,
            info=b"X3DH",
        )
        shared_key = hkdf.derive(f + key_material)

        # --- Compute associated data (same as sender) ---
        associated_data = alice_ik_public_bytes + bob_ik_public_bytes

        return X3DHResult(
            shared_key=shared_key,
            associated_data=associated_data,
            ephemeral_public_key=alice_ephemeral_public_b64,
            used_one_time_prekey=bob_one_time_prekey_private_b64 is not None,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

x3dh_manager = X3DHManager()
