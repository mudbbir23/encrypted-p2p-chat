"""
Cryptographic round-trip tests for X3DH and Double Ratchet.

These tests verify the fundamental security properties:
1. Sender and receiver derive the SAME shared key from X3DH
2. Double Ratchet encrypted messages decrypt correctly
3. Out-of-order messages decrypt correctly via skipped key cache
4. Signed prekey signature verification works correctly
5. Tampered ciphertext is rejected
"""
from __future__ import annotations

import os
import pytest

from app.core.encryption.x3dh_manager import X3DHManager, PreKeyBundle, x3dh_manager
from app.core.encryption.double_ratchet import (
    DoubleRatchet,
    DoubleRatchetState,
    EncryptedMessage,
    MessageHeader,
    double_ratchet,
)


# ---------------------------------------------------------------------------
# X3DH Tests
# ---------------------------------------------------------------------------

class TestX3DH:

    def setup_method(self):
        self.manager = X3DHManager()

    def _generate_alice_keys(self):
        ik_x25519 = self.manager.generate_identity_keypair_x25519()
        ik_ed25519 = self.manager.generate_identity_keypair_ed25519()
        return ik_x25519, ik_ed25519

    def _generate_bob_bundle(self):
        ik_x25519 = self.manager.generate_identity_keypair_x25519()
        ik_ed25519 = self.manager.generate_identity_keypair_ed25519()
        spk, spk_sig = self.manager.generate_signed_prekey(ik_ed25519.private_key_b64)
        opks = self.manager.generate_one_time_prekeys(1)
        bundle = PreKeyBundle(
            user_id="bob",
            identity_key_x25519=ik_x25519.public_key_b64,
            identity_key_ed25519=ik_ed25519.public_key_b64,
            signed_prekey=spk.public_key_b64,
            signed_prekey_signature=spk_sig,
            one_time_prekey=opks[0].public_key_b64,
        )
        return bundle, ik_x25519, ik_ed25519, spk, opks[0]

    def test_shared_key_is_identical(self):
        """Alice and Bob must derive the same shared key."""
        alice_ik_x25519, alice_ik_ed25519 = self._generate_alice_keys()
        bob_bundle, bob_ik_x25519, bob_ik_ed25519, bob_spk, bob_opk = self._generate_bob_bundle()

        # Alice performs sender-side X3DH
        alice_result = self.manager.perform_x3dh_sender(
            alice_identity_private_x25519_b64=alice_ik_x25519.private_key_b64,
            alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
            bob_bundle=bob_bundle,
        )

        # Bob performs receiver-side X3DH
        bob_result = self.manager.perform_x3dh_receiver(
            bob_identity_private_x25519_b64=bob_ik_x25519.private_key_b64,
            bob_identity_public_x25519_b64=bob_ik_x25519.public_key_b64,
            bob_signed_prekey_private_b64=bob_spk.private_key_b64,
            alice_ephemeral_public_b64=alice_result.ephemeral_public_key,
            alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
            bob_one_time_prekey_private_b64=bob_opk.private_key_b64,
        )

        assert alice_result.shared_key == bob_result.shared_key, (
            "X3DH shared keys do not match — CRITICAL cryptographic failure"
        )
        assert len(alice_result.shared_key) == 32, "Shared key must be 32 bytes"

    def test_associated_data_matches(self):
        """Associated data (IK_A || IK_B) must be identical on both sides."""
        alice_ik_x25519, alice_ik_ed25519 = self._generate_alice_keys()
        bob_bundle, bob_ik_x25519, _, bob_spk, bob_opk = self._generate_bob_bundle()

        alice_result = self.manager.perform_x3dh_sender(
            alice_identity_private_x25519_b64=alice_ik_x25519.private_key_b64,
            alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
            bob_bundle=bob_bundle,
        )
        bob_result = self.manager.perform_x3dh_receiver(
            bob_identity_private_x25519_b64=bob_ik_x25519.private_key_b64,
            bob_identity_public_x25519_b64=bob_ik_x25519.public_key_b64,
            bob_signed_prekey_private_b64=bob_spk.private_key_b64,
            alice_ephemeral_public_b64=alice_result.ephemeral_public_key,
            alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
            bob_one_time_prekey_private_b64=bob_opk.private_key_b64,
        )

        assert alice_result.associated_data == bob_result.associated_data
        assert len(alice_result.associated_data) == 64  # 32 + 32 bytes

    def test_signed_prekey_verification_valid(self):
        """A valid signature should verify correctly."""
        ik_x25519, ik_ed25519 = self._generate_alice_keys()
        spk, sig = self.manager.generate_signed_prekey(ik_ed25519.private_key_b64)

        assert self.manager.verify_signed_prekey(
            signed_prekey_b64=spk.public_key_b64,
            signature_b64=sig,
            identity_public_ed25519_b64=ik_ed25519.public_key_b64,
        ) is True

    def test_signed_prekey_verification_tampered(self):
        """A tampered signature should fail verification."""
        ik_x25519, ik_ed25519 = self._generate_alice_keys()
        spk, sig = self.manager.generate_signed_prekey(ik_ed25519.private_key_b64)

        # Tamper with the first character of the signature
        tampered_sig = ("X" + sig[1:]) if sig[0] != "X" else ("Y" + sig[1:])

        assert self.manager.verify_signed_prekey(
            signed_prekey_b64=spk.public_key_b64,
            signature_b64=tampered_sig,
            identity_public_ed25519_b64=ik_ed25519.public_key_b64,
        ) is False

    def test_invalid_signed_prekey_aborts_x3dh(self):
        """X3DH must raise ValueError if SPK signature is invalid."""
        alice_ik_x25519, alice_ik_ed25519 = self._generate_alice_keys()
        bob_bundle, _, _, _, _ = self._generate_bob_bundle()

        # Corrupt the signature
        bad_sig = "AAAA" + bob_bundle.signed_prekey_signature[4:]
        alice_ik_ed25519_new = self.manager.generate_identity_keypair_ed25519()
        # Use wrong Ed25519 key in bundle
        tampered_bundle = PreKeyBundle(
            user_id=bob_bundle.user_id,
            identity_key_x25519=bob_bundle.identity_key_x25519,
            identity_key_ed25519=self.manager.generate_identity_keypair_ed25519().public_key_b64,
            signed_prekey=bob_bundle.signed_prekey,
            signed_prekey_signature=bob_bundle.signed_prekey_signature,
            one_time_prekey=bob_bundle.one_time_prekey,
        )

        with pytest.raises(ValueError, match="Signed prekey signature verification failed"):
            self.manager.perform_x3dh_sender(
                alice_identity_private_x25519_b64=alice_ik_x25519.private_key_b64,
                alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
                bob_bundle=tampered_bundle,
            )

    def test_x3dh_without_opk(self):
        """X3DH should work without a one-time prekey (3-DH variant)."""
        alice_ik_x25519, _ = self._generate_alice_keys()
        bob_bundle, bob_ik_x25519, _, bob_spk, _ = self._generate_bob_bundle()

        # Bundle without OPK
        bundle_no_opk = PreKeyBundle(
            user_id=bob_bundle.user_id,
            identity_key_x25519=bob_bundle.identity_key_x25519,
            identity_key_ed25519=bob_bundle.identity_key_ed25519,
            signed_prekey=bob_bundle.signed_prekey,
            signed_prekey_signature=bob_bundle.signed_prekey_signature,
            one_time_prekey=None,
        )

        alice_result = self.manager.perform_x3dh_sender(
            alice_identity_private_x25519_b64=alice_ik_x25519.private_key_b64,
            alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
            bob_bundle=bundle_no_opk,
        )
        bob_result = self.manager.perform_x3dh_receiver(
            bob_identity_private_x25519_b64=bob_ik_x25519.private_key_b64,
            bob_identity_public_x25519_b64=bob_ik_x25519.public_key_b64,
            bob_signed_prekey_private_b64=bob_spk.private_key_b64,
            alice_ephemeral_public_b64=alice_result.ephemeral_public_key,
            alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
            bob_one_time_prekey_private_b64=None,
        )

        assert alice_result.shared_key == bob_result.shared_key
        assert not alice_result.used_one_time_prekey


# ---------------------------------------------------------------------------
# Double Ratchet Tests
# ---------------------------------------------------------------------------

def make_session_pair():
    """Create a pair of initialized Double Ratchet states (alice, bob)."""
    manager = X3DHManager()
    ratchet = DoubleRatchet()

    alice_ik_x25519 = manager.generate_identity_keypair_x25519()
    alice_ik_ed25519 = manager.generate_identity_keypair_ed25519()
    bob_ik_x25519 = manager.generate_identity_keypair_x25519()
    bob_ik_ed25519 = manager.generate_identity_keypair_ed25519()
    bob_spk, bob_spk_sig = manager.generate_signed_prekey(bob_ik_ed25519.private_key_b64)

    bundle = PreKeyBundle(
        user_id="bob",
        identity_key_x25519=bob_ik_x25519.public_key_b64,
        identity_key_ed25519=bob_ik_ed25519.public_key_b64,
        signed_prekey=bob_spk.public_key_b64,
        signed_prekey_signature=bob_spk_sig,
    )

    alice_x3dh = manager.perform_x3dh_sender(
        alice_identity_private_x25519_b64=alice_ik_x25519.private_key_b64,
        alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
        bob_bundle=bundle,
    )
    bob_x3dh = manager.perform_x3dh_receiver(
        bob_identity_private_x25519_b64=bob_ik_x25519.private_key_b64,
        bob_identity_public_x25519_b64=bob_ik_x25519.public_key_b64,
        bob_signed_prekey_private_b64=bob_spk.private_key_b64,
        alice_ephemeral_public_b64=alice_x3dh.ephemeral_public_key,
        alice_identity_public_x25519_b64=alice_ik_x25519.public_key_b64,
    )

    alice_state = ratchet.initialize_sender(
        shared_key=alice_x3dh.shared_key,
        bob_signed_prekey_public_b64=bob_spk.public_key_b64,
    )
    bob_state = ratchet.initialize_receiver(
        shared_key=bob_x3dh.shared_key,
        bob_signed_prekey_private_b64=bob_spk.private_key_b64,
        bob_signed_prekey_public_b64=bob_spk.public_key_b64,
    )
    ad = alice_x3dh.associated_data

    return alice_state, bob_state, ad, ratchet


class TestDoubleRatchet:

    def test_basic_encrypt_decrypt(self):
        """A message encrypted by Alice should be decrypted by Bob."""
        alice_state, bob_state, ad, ratchet = make_session_pair()
        plaintext = b"Hello, Bob! This is encrypted."

        alice_state, encrypted = ratchet.encrypt_message(alice_state, plaintext, ad)
        bob_state, decrypted = ratchet.decrypt_message(bob_state, encrypted, ad)

        assert decrypted == plaintext

    def test_multiple_messages_in_order(self):
        """Multiple messages in order all decrypt correctly."""
        alice_state, bob_state, ad, ratchet = make_session_pair()

        messages = [f"Message {i}".encode() for i in range(10)]
        encrypted_msgs = []

        for msg in messages:
            alice_state, enc = ratchet.encrypt_message(alice_state, msg, ad)
            encrypted_msgs.append(enc)

        for i, enc in enumerate(encrypted_msgs):
            bob_state, dec = ratchet.decrypt_message(bob_state, enc, ad)
            assert dec == messages[i], f"Message {i} failed to decrypt"

    def test_bidirectional_conversation(self):
        """A full back-and-forth conversation decrypts correctly."""
        alice_state, bob_state, ad, ratchet = make_session_pair()

        # Alice sends
        alice_state, enc1 = ratchet.encrypt_message(alice_state, b"Hey Bob!", ad)
        bob_state, dec1 = ratchet.decrypt_message(bob_state, enc1, ad)
        assert dec1 == b"Hey Bob!"

        # Bob replies
        bob_state, enc2 = ratchet.encrypt_message(bob_state, b"Hey Alice!", ad)
        alice_state, dec2 = ratchet.decrypt_message(alice_state, enc2, ad)
        assert dec2 == b"Hey Alice!"

        # Alice sends again
        alice_state, enc3 = ratchet.encrypt_message(alice_state, b"How are you?", ad)
        bob_state, dec3 = ratchet.decrypt_message(bob_state, enc3, ad)
        assert dec3 == b"How are you?"

    def test_tampered_ciphertext_rejected(self):
        """Tampered ciphertext must raise ValueError."""
        alice_state, bob_state, ad, ratchet = make_session_pair()

        alice_state, encrypted = ratchet.encrypt_message(alice_state, b"Secret message", ad)

        import base64
        ct_bytes = base64.urlsafe_b64decode(encrypted.ciphertext_b64 + "==")
        # Flip the first byte of ciphertext
        tampered = bytes([ct_bytes[0] ^ 0xFF]) + ct_bytes[1:]
        tampered_b64 = base64.urlsafe_b64encode(tampered).rstrip(b"=").decode()

        tampered_msg = EncryptedMessage(
            ciphertext_b64=tampered_b64,
            nonce_b64=encrypted.nonce_b64,
            header=encrypted.header,
        )

        with pytest.raises(ValueError, match="Message authentication failed"):
            ratchet.decrypt_message(bob_state, tampered_msg, ad)

    def test_wrong_associated_data_rejected(self):
        """Wrong associated data (AD) must cause AES-GCM authentication failure."""
        alice_state, bob_state, ad, ratchet = make_session_pair()

        alice_state, encrypted = ratchet.encrypt_message(alice_state, b"Secret message", ad)
        wrong_ad = b"wrong_associated_data"

        with pytest.raises(ValueError):
            ratchet.decrypt_message(bob_state, encrypted, wrong_ad)

    def test_state_serialization_roundtrip(self):
        """State must serialize and deserialize without loss."""
        alice_state, bob_state, ad, ratchet = make_session_pair()

        alice_state, enc = ratchet.encrypt_message(alice_state, b"test", ad)

        # Serialize and deserialize
        alice_json = alice_state.to_json()
        alice_restored = DoubleRatchetState.from_json(alice_json)

        # The restored state should produce valid encryption
        alice_restored, enc2 = ratchet.encrypt_message(alice_restored, b"test2", ad)
        bob_state, _ = ratchet.decrypt_message(bob_state, enc, ad)
        bob_state, dec2 = ratchet.decrypt_message(bob_state, enc2, ad)
        assert dec2 == b"test2"

    def test_out_of_order_messages(self):
        """Messages delivered out of order must still decrypt correctly."""
        alice_state, bob_state, ad, ratchet = make_session_pair()

        # Alice sends 3 messages
        alice_state, enc1 = ratchet.encrypt_message(alice_state, b"Message 1", ad)
        alice_state, enc2 = ratchet.encrypt_message(alice_state, b"Message 2", ad)
        alice_state, enc3 = ratchet.encrypt_message(alice_state, b"Message 3", ad)

        # Bob receives in reverse order
        bob_state, dec3 = ratchet.decrypt_message(bob_state, enc3, ad)
        bob_state, dec2 = ratchet.decrypt_message(bob_state, enc2, ad)
        bob_state, dec1 = ratchet.decrypt_message(bob_state, enc1, ad)

        assert dec1 == b"Message 1"
        assert dec2 == b"Message 2"
        assert dec3 == b"Message 3"
