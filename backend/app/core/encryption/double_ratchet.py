"""
Double Ratchet Algorithm implementation.

Implements the Signal Protocol Double Ratchet for per-message forward secrecy
and post-compromise security.

Reference: https://signal.org/docs/specifications/doubleratchet/

Security properties:
- Forward secrecy: Compromising key material at time T does not expose messages before T.
  HMAC is a one-way function, so chain_key[N] cannot be inverted to get chain_key[N-1].
- Post-compromise security: After a chain is compromised, a DH ratchet step refreshes
  the root key with fresh entropy, healing the conversation.
- Out-of-order delivery: Skipped message keys are cached and evicted safely.

Limits enforced (from config.py):
- MAX_SKIP_MESSAGE_KEYS = 1000  (max gap size in one ratchet step)
- MAX_CACHED_MESSAGE_KEYS = 2000 (total cached skipped keys per state)
- AES_GCM_NONCE_SIZE = 12 bytes
- HKDF_OUTPUT_SIZE = 32 bytes

CRITICAL: Never reuse a nonce with the same key. Each encrypt call generates
os.urandom(12) per NIST SP 800-38D.
"""
from __future__ import annotations

import base64
import hmac as _hmac
import json
import os
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import settings


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    return base64.urlsafe_b64decode(data)


def _load_x25519_private(b64: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_b64d(b64))


def _load_x25519_public(b64: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(_b64d(b64))


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


# ---------------------------------------------------------------------------
# State dataclass
# ---------------------------------------------------------------------------

@dataclass
class DoubleRatchetState:
    """
    Complete state of one side of a Double Ratchet session.

    Serializes cleanly to/from JSON (all byte fields are base64url strings).
    """
    root_key: bytes

    # Sending chain
    sending_chain_key: Optional[bytes] = None
    sending_message_number: int = 0
    dh_sending_private_b64: Optional[str] = None
    dh_sending_public_b64: Optional[str] = None

    # Receiving chain
    receiving_chain_key: Optional[bytes] = None
    receiving_message_number: int = 0
    dh_peer_public_b64: Optional[str] = None

    # Number of messages in the PREVIOUS sending chain (put into message headers)
    previous_sending_chain_count: int = 0

    # Skipped message key cache: {(dh_pub_b64, msg_number): message_key_bytes}
    skipped_message_keys: dict[tuple[str, int], bytes] = field(default_factory=dict)

    def to_json(self) -> dict:
        """Serialize to a JSON-safe dict (base64url encode all bytes fields)."""
        skipped = {
            f"{k[0]}:{k[1]}": _b64e(v)
            for k, v in self.skipped_message_keys.items()
        }
        return {
            "root_key": _b64e(self.root_key),
            "sending_chain_key": _b64e(self.sending_chain_key) if self.sending_chain_key else None,
            "sending_message_number": self.sending_message_number,
            "dh_sending_private_b64": self.dh_sending_private_b64,
            "dh_sending_public_b64": self.dh_sending_public_b64,
            "receiving_chain_key": _b64e(self.receiving_chain_key) if self.receiving_chain_key else None,
            "receiving_message_number": self.receiving_message_number,
            "dh_peer_public_b64": self.dh_peer_public_b64,
            "previous_sending_chain_count": self.previous_sending_chain_count,
            "skipped_message_keys": skipped,
        }

    @classmethod
    def from_json(cls, data: dict) -> "DoubleRatchetState":
        """Deserialize from a JSON dict."""
        skipped: dict[tuple[str, int], bytes] = {}
        for composite_key, v in data.get("skipped_message_keys", {}).items():
            dh_pub, msg_num_str = composite_key.rsplit(":", 1)
            skipped[(dh_pub, int(msg_num_str))] = _b64d(v)

        return cls(
            root_key=_b64d(data["root_key"]),
            sending_chain_key=_b64d(data["sending_chain_key"]) if data.get("sending_chain_key") else None,
            sending_message_number=data.get("sending_message_number", 0),
            dh_sending_private_b64=data.get("dh_sending_private_b64"),
            dh_sending_public_b64=data.get("dh_sending_public_b64"),
            receiving_chain_key=_b64d(data["receiving_chain_key"]) if data.get("receiving_chain_key") else None,
            receiving_message_number=data.get("receiving_message_number", 0),
            dh_peer_public_b64=data.get("dh_peer_public_b64"),
            previous_sending_chain_count=data.get("previous_sending_chain_count", 0),
            skipped_message_keys=skipped,
        )


@dataclass
class MessageHeader:
    """
    Double Ratchet message header.
    Sent alongside ciphertext so the receiver can ratchet correctly.
    """
    dh_public_key: str   # Sender's current DH public key (base64url)
    message_number: int  # Message number in current sending chain
    prev_chain_count: int  # Messages in previous sending chain

    def to_json(self) -> str:
        return json.dumps({
            "dh": self.dh_public_key,
            "n": self.message_number,
            "pn": self.prev_chain_count,
        }, separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "MessageHeader":
        d = json.loads(s)
        return cls(
            dh_public_key=d["dh"],
            message_number=d["n"],
            prev_chain_count=d["pn"],
        )


@dataclass
class EncryptedMessage:
    """Output of a Double Ratchet encrypt operation."""
    ciphertext_b64: str  # base64url AES-256-GCM ciphertext (includes auth tag)
    nonce_b64: str        # base64url 12-byte nonce
    header: MessageHeader


# ---------------------------------------------------------------------------
# KDF chains
# ---------------------------------------------------------------------------

class DoubleRatchet:
    """
    Stateless Double Ratchet engine.

    Methods accept and return DoubleRatchetState explicitly.
    The caller is responsible for persisting state between calls.
    """

    # -----------------------------------------------------------------------
    # KDF chains
    # -----------------------------------------------------------------------

    def _kdf_rk(
        self, root_key: bytes, dh_output: bytes
    ) -> tuple[bytes, bytes]:
        """
        KDF_RK: Root key chain derivation.

        Advances the root chain using fresh DH output. Produces a new root key
        and a new chain key. Used during DH ratchet steps.

        HKDF-SHA256 with current root_key as salt and dh_output as IKM.
        Output is 64 bytes, split into two 32-byte keys.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=settings.HKDF_OUTPUT_SIZE * 2,  # 64 bytes total
            salt=root_key,
            info=b"",
        )
        output = hkdf.derive(dh_output)
        new_root_key = output[: settings.HKDF_OUTPUT_SIZE]
        new_chain_key = output[settings.HKDF_OUTPUT_SIZE :]
        return new_root_key, new_chain_key

    def _kdf_ck(self, chain_key: bytes) -> tuple[bytes, bytes]:
        """
        KDF_CK: Symmetric chain key derivation.

        Advances a symmetric chain. Produces the next chain key and a message key.
        Uses HMAC-SHA256 with constants 0x01 and 0x02 to ensure independence:
        - Knowing the message key does not reveal the next chain key
        - Knowing the next chain key does not reveal the message key

        This one-way function ensures forward secrecy within a DH epoch.
        """
        # HMAC(chain_key, 0x01) → next chain key
        h_chain = hmac.HMAC(chain_key, hashes.SHA256())
        h_chain.update(b"\x01")
        next_chain_key = h_chain.finalize()

        # HMAC(chain_key, 0x02) → message key
        h_message = hmac.HMAC(chain_key, hashes.SHA256())
        h_message.update(b"\x02")
        message_key = h_message.finalize()

        return next_chain_key, message_key

    # -----------------------------------------------------------------------
    # AES-256-GCM symmetric encryption
    # -----------------------------------------------------------------------

    def _encrypt_with_message_key(
        self,
        message_key: bytes,
        plaintext: bytes,
        associated_data: bytes,
    ) -> tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM using the given message key.

        Returns: (nonce, ciphertext_with_tag)

        The nonce is 12 bytes from os.urandom — NEVER reused.
        The ciphertext includes the 16-byte GCM authentication tag.
        """
        nonce = os.urandom(settings.AES_GCM_NONCE_SIZE)
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def _decrypt_with_message_key(
        self,
        message_key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes,
    ) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM using the given message key.

        Raises ValueError if the authentication tag is invalid (tampered data,
        wrong key, or incorrect associated data).
        """
        aesgcm = AESGCM(message_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception:
            raise ValueError("Message authentication failed: tampered or corrupted ciphertext")

    # -----------------------------------------------------------------------
    # DH ratchet steps
    # -----------------------------------------------------------------------

    def _dh_ratchet_send(
        self, state: DoubleRatchetState
    ) -> DoubleRatchetState:
        """
        Advance the DH ratchet for sending.

        Generates a new DH keypair and derives new root + sending chain keys.
        Called automatically when the sending chain needs to be initialized
        (i.e., when Alice starts a new DH epoch by sending after Bob responded).
        """
        if state.dh_peer_public_b64 is None:
            raise RuntimeError("Cannot perform DH ratchet: no peer public key set")

        # Save the current sending chain count for inclusion in outgoing headers
        state.previous_sending_chain_count = state.sending_message_number

        # Generate a new DH keypair for this epoch
        new_dh_private = X25519PrivateKey.generate()
        new_dh_public = new_dh_private.public_key()
        new_dh_private_b64 = _b64e(_serialize_x25519_private(new_dh_private))
        new_dh_public_b64 = _b64e(_serialize_x25519_public(new_dh_public))

        # DH output with peer's last known public key
        peer_public = _load_x25519_public(state.dh_peer_public_b64)
        dh_output = new_dh_private.exchange(peer_public)

        # Derive new root key and sending chain key
        new_root_key, new_sending_chain_key = self._kdf_rk(state.root_key, dh_output)

        state.root_key = new_root_key
        state.sending_chain_key = new_sending_chain_key
        state.sending_message_number = 0
        state.dh_sending_private_b64 = new_dh_private_b64
        state.dh_sending_public_b64 = new_dh_public_b64
        return state

    def _dh_ratchet_receive(
        self,
        state: DoubleRatchetState,
        new_peer_dh_public_b64: str,
    ) -> DoubleRatchetState:
        """
        Advance the DH ratchet for receiving.

        When a message arrives with a new DH public key from the peer (one we
        have not seen before), we perform TWO DH operations:

        1. DH with our current private key + peer's new public key → new receiving chain
        2. Generate a new private key and DH with peer's new public key → new sending chain

        This double step ensures both chains are refreshed simultaneously,
        providing post-compromise security from this point forward.
        """
        state.previous_sending_chain_count = state.sending_message_number
        state.receiving_message_number = 0
        state.dh_peer_public_b64 = new_peer_dh_public_b64

        peer_public = _load_x25519_public(new_peer_dh_public_b64)

        # Step 1: Derive new receiving chain from existing DH private key
        if state.dh_sending_private_b64 is not None:
            current_dh_private = _load_x25519_private(state.dh_sending_private_b64)
            dh_output_recv = current_dh_private.exchange(peer_public)
            new_root_key, new_recv_chain_key = self._kdf_rk(state.root_key, dh_output_recv)
            state.root_key = new_root_key
            state.receiving_chain_key = new_recv_chain_key

        # Step 2: Generate new DH keypair and derive new sending chain
        new_dh_private = X25519PrivateKey.generate()
        new_dh_public = new_dh_private.public_key()
        new_dh_private_b64 = _b64e(_serialize_x25519_private(new_dh_private))
        new_dh_public_b64 = _b64e(_serialize_x25519_public(new_dh_public))

        dh_output_send = new_dh_private.exchange(peer_public)
        new_root_key2, new_send_chain_key = self._kdf_rk(state.root_key, dh_output_send)
        state.root_key = new_root_key2
        state.sending_chain_key = new_send_chain_key
        state.sending_message_number = 0
        state.dh_sending_private_b64 = new_dh_private_b64
        state.dh_sending_public_b64 = new_dh_public_b64

        return state

    # -----------------------------------------------------------------------
    # Skipped message key management
    # -----------------------------------------------------------------------

    def _store_skipped_message_keys(
        self,
        state: DoubleRatchetState,
        dh_public_key_b64: str,
        until_message_number: int,
    ) -> DoubleRatchetState:
        """
        Derive and cache message keys for skipped message numbers.

        Called when a received message has a higher number than expected,
        indicating earlier messages have not yet arrived.

        Security limits:
        - Refuses to skip more than MAX_SKIP_MESSAGE_KEYS in one step.
        - Evicts oldest cached keys if cache exceeds MAX_CACHED_MESSAGE_KEYS.
        """
        gap = until_message_number - state.receiving_message_number
        if gap > settings.MAX_SKIP_MESSAGE_KEYS:
            raise ValueError(
                f"Refusing to skip {gap} message keys (max {settings.MAX_SKIP_MESSAGE_KEYS}). "
                "This may indicate a replay or DoS attack."
            )

        if state.receiving_chain_key is None:
            raise RuntimeError("Cannot store skipped keys: receiving chain key is not set")

        chain_key = state.receiving_chain_key
        for msg_num in range(state.receiving_message_number, until_message_number):
            chain_key, message_key = self._kdf_ck(chain_key)
            state.skipped_message_keys[(dh_public_key_b64, msg_num)] = message_key

        state.receiving_chain_key = chain_key

        # Evict excess cached keys (oldest first, by insertion order)
        self._evict_oldest_skipped_keys(state)
        return state

    def _evict_oldest_skipped_keys(self, state: DoubleRatchetState) -> None:
        """Remove oldest skipped keys when cache exceeds MAX_CACHED_MESSAGE_KEYS."""
        excess = len(state.skipped_message_keys) - settings.MAX_CACHED_MESSAGE_KEYS
        if excess > 0:
            keys_to_remove = list(state.skipped_message_keys.keys())[:excess]
            for k in keys_to_remove:
                del state.skipped_message_keys[k]

    def _try_skipped_message_key(
        self,
        state: DoubleRatchetState,
        header: MessageHeader,
    ) -> Optional[bytes]:
        """
        Try to find a cached skipped message key for this header.

        Returns the message key if found (and removes it from cache — one use only),
        or None if not found.
        """
        cache_key = (header.dh_public_key, header.message_number)
        if cache_key in state.skipped_message_keys:
            message_key = state.skipped_message_keys.pop(cache_key)
            return message_key
        return None

    # -----------------------------------------------------------------------
    # Initialization
    # -----------------------------------------------------------------------

    def initialize_sender(
        self,
        shared_key: bytes,
        bob_signed_prekey_public_b64: str,
    ) -> DoubleRatchetState:
        """
        Initialize state for the sender (Alice) after X3DH.

        The X3DH shared key becomes the initial root key.
        Bob's signed prekey becomes the initial peer DH public key.
        Alice immediately performs a DH ratchet step to derive the first
        sending chain key.

        Returns an initialized DoubleRatchetState ready for encrypt_message.
        """
        # Generate Alice's first DH keypair
        alice_dh_private = X25519PrivateKey.generate()
        alice_dh_public = alice_dh_private.public_key()

        state = DoubleRatchetState(
            root_key=shared_key,
            dh_peer_public_b64=bob_signed_prekey_public_b64,
            dh_sending_private_b64=_b64e(_serialize_x25519_private(alice_dh_private)),
            dh_sending_public_b64=_b64e(_serialize_x25519_public(alice_dh_public)),
        )

        # Derive the first sending chain via DH with Bob's SPK
        peer_public = _load_x25519_public(bob_signed_prekey_public_b64)
        dh_output = alice_dh_private.exchange(peer_public)
        new_root_key, new_sending_chain_key = self._kdf_rk(state.root_key, dh_output)
        state.root_key = new_root_key
        state.sending_chain_key = new_sending_chain_key

        return state

    def initialize_receiver(
        self,
        shared_key: bytes,
        bob_signed_prekey_private_b64: str,
        bob_signed_prekey_public_b64: str,
    ) -> DoubleRatchetState:
        """
        Initialize state for the receiver (Bob) after X3DH.

        Bob uses his SPK private key as the initial DH keypair.
        The sending chain starts empty (Bob hasn't sent anything yet).
        """
        bob_spk_private = _load_x25519_private(bob_signed_prekey_private_b64)
        bob_spk_public = bob_spk_private.public_key()

        state = DoubleRatchetState(
            root_key=shared_key,
            dh_sending_private_b64=bob_signed_prekey_private_b64,
            dh_sending_public_b64=bob_signed_prekey_public_b64,
        )
        return state

    # -----------------------------------------------------------------------
    # Encrypt
    # -----------------------------------------------------------------------

    def encrypt_message(
        self,
        state: DoubleRatchetState,
        plaintext: bytes,
        associated_data: bytes,
    ) -> tuple[DoubleRatchetState, EncryptedMessage]:
        """
        Encrypt a message and advance the sending chain.

        The message key is derived from the current sending chain, used
        for AES-256-GCM encryption, then discarded. The chain key advances.

        Returns the updated state (caller MUST persist this) and the encrypted message.
        """
        if state.sending_chain_key is None:
            # First message — need to DH ratchet to establish the sending chain
            if state.dh_peer_public_b64 is None:
                raise RuntimeError("Cannot encrypt: no peer public key and no sending chain")
            state = self._dh_ratchet_send(state)

        assert state.sending_chain_key is not None  # type checker hint

        # Advance the symmetric chain
        next_chain_key, message_key = self._kdf_ck(state.sending_chain_key)
        state.sending_chain_key = next_chain_key

        # Build header before encrypting
        if state.dh_sending_public_b64 is None:
            raise RuntimeError("Cannot encrypt: sending DH public key not set")

        header = MessageHeader(
            dh_public_key=state.dh_sending_public_b64,
            message_number=state.sending_message_number,
            prev_chain_count=state.previous_sending_chain_count,
        )

        # Encrypt
        nonce, ciphertext = self._encrypt_with_message_key(
            message_key, plaintext, associated_data
        )

        # Advance message counter AFTER successful encryption
        state.sending_message_number += 1

        encrypted = EncryptedMessage(
            ciphertext_b64=_b64e(ciphertext),
            nonce_b64=_b64e(nonce),
            header=header,
        )
        return state, encrypted

    # -----------------------------------------------------------------------
    # Decrypt
    # -----------------------------------------------------------------------

    def decrypt_message(
        self,
        state: DoubleRatchetState,
        encrypted: EncryptedMessage,
        associated_data: bytes,
    ) -> tuple[DoubleRatchetState, bytes]:
        """
        Decrypt a received message and advance the receiving chain.

        Handles three cases:
        1. Message key is in the skipped key cache (out-of-order late arrival)
        2. Message is in the current receiving chain (in-order)
        3. Message has a new DH key (triggers a DH ratchet step)

        Returns the updated state and decrypted plaintext.

        Raises ValueError on authentication failure (tampered data or wrong key).
        """
        nonce = _b64d(encrypted.nonce_b64)
        ciphertext = _b64d(encrypted.ciphertext_b64)
        header = encrypted.header

        # --- Case 1: Try skipped message keys first ---
        skipped_message_key = self._try_skipped_message_key(state, header)
        if skipped_message_key is not None:
            plaintext = self._decrypt_with_message_key(
                skipped_message_key, nonce, ciphertext, associated_data
            )
            return state, plaintext

        # --- Case 2 or 3: Is this a new DH epoch? ---
        is_new_dh = (header.dh_public_key != state.dh_peer_public_b64)

        if is_new_dh:
            # Store skipped keys from the previous DH epoch before ratcheting
            if state.dh_peer_public_b64 is not None and state.receiving_chain_key is not None:
                self._store_skipped_message_keys(
                    state,
                    state.dh_peer_public_b64,
                    header.prev_chain_count,
                )

            # Perform DH ratchet step to derive new receiving chain
            state = self._dh_ratchet_receive(state, header.dh_public_key)

        # Store any skipped keys in the current receiving chain
        if (state.receiving_chain_key is not None and
                header.message_number > state.receiving_message_number):
            self._store_skipped_message_keys(
                state,
                header.dh_public_key,
                header.message_number,
            )

        # Advance receiving chain to get the message key
        if state.receiving_chain_key is None:
            raise RuntimeError("Cannot decrypt: receiving chain key is not set")

        next_chain_key, message_key = self._kdf_ck(state.receiving_chain_key)
        state.receiving_chain_key = next_chain_key
        state.receiving_message_number += 1

        plaintext = self._decrypt_with_message_key(
            message_key, nonce, ciphertext, associated_data
        )
        return state, plaintext


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

double_ratchet = DoubleRatchet()
