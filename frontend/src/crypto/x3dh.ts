/**
 * Client-side X3DH key agreement using @noble/curves X25519.
 *
 * Used by Alice (the initiator) to establish a shared key with Bob
 * asynchronously (Bob may be offline).
 *
 * Performs:
 *   DH1 = X25519(IK_A, SPK_B)
 *   DH2 = X25519(EK_A, IK_B)
 *   DH3 = X25519(EK_A, SPK_B)
 *   DH4 = X25519(EK_A, OPK_B)   ← only if OPK available
 *   SK  = HKDF(DH1 || DH2 || DH3 [|| DH4])
 */

import { x25519 } from "@noble/curves/ed25519";
import { hkdfDerive, b64Encode, b64Decode, randomBytes } from "./primitives";

export interface X3DHBundle {
  /** Bob's X25519 identity public key */
  identity_key_x25519: string;         // base64url
  /** Bob's Ed25519 identity public key (for SPK signature verification) */
  identity_key_ed25519: string;        // base64url
  /** Bob's signed prekey public key */
  signed_prekey: string;               // base64url
  /** Ed25519 signature over signed_prekey by identity_key_ed25519 */
  signed_prekey_signature: string;     // base64url
  /** Bob's one-time prekey (optional) */
  one_time_prekey?: string | null;
  one_time_prekey_id?: number | null;
}

export interface X3DHSenderResult {
  /** Derived 32-byte shared key */
  sharedKey: Uint8Array;
  /** Alice's ephemeral public key (must be sent to Bob in the message header) */
  ephemeralPublicKey: string;           // base64url
  /** Associated data = IK_A_pub || IK_B_pub (both X25519) */
  associatedData: Uint8Array;
  /** Whether an OPK was consumed */
  usedOneTimePrekey: boolean;
  one_time_prekey_id?: number | null;
}

const HKDF_INFO_X3DH = "E2EChatX3DH";
const X3DH_SALT = new Uint8Array(32); // 32 zero bytes per Signal spec

/**
 * Alice performs X3DH as the initiator.
 *
 * @param aliceIdentityPriv Alice's X25519 private key (from KeyStore)
 * @param aliceIdentityPub  Alice's X25519 public key
 * @param bobBundle         Bob's prekey bundle (from server)
 */
export async function x3dhSender(
  aliceIdentityPriv: Uint8Array,
  aliceIdentityPub: Uint8Array,
  bobBundle: X3DHBundle
): Promise<X3DHSenderResult> {
  // Decode Bob's public keys
  const ikB = b64Decode(bobBundle.identity_key_x25519);   // Bob IK (X25519)
  const spkB = b64Decode(bobBundle.signed_prekey);        // Bob SPK

  // Generate Alice's ephemeral keypair
  const ekPriv = randomBytes(32); // X25519 private key
  const ekPub = x25519.getPublicKey(ekPriv);

  // Perform the 3 (or 4) DH operations
  // DH1 = DH(IK_A, SPK_B)   — authenticates Alice to Bob
  const dh1 = x25519.getSharedSecret(aliceIdentityPriv, spkB);

  // DH2 = DH(EK_A, IK_B)    — forward secrecy from ephemeral key
  const dh2 = x25519.getSharedSecret(ekPriv, ikB);

  // DH3 = DH(EK_A, SPK_B)   — ties ephemeral to SPK
  const dh3 = x25519.getSharedSecret(ekPriv, spkB);

  let dhInput: Uint8Array;
  let usedOPK = false;

  if (bobBundle.one_time_prekey) {
    const opkB = b64Decode(bobBundle.one_time_prekey);
    // DH4 = DH(EK_A, OPK_B)  — one-time forward secrecy
    const dh4 = x25519.getSharedSecret(ekPriv, opkB);

    dhInput = new Uint8Array([...dh1, ...dh2, ...dh3, ...dh4]);
    usedOPK = true;
  } else {
    dhInput = new Uint8Array([...dh1, ...dh2, ...dh3]);
  }

  // Derive 32-byte shared key with HKDF-SHA-256
  const sharedKey = await hkdfDerive(dhInput, X3DH_SALT, HKDF_INFO_X3DH, 32);

  // Associated data: IK_A_pub || IK_B_pub (concatenated public keys)
  const associatedData = new Uint8Array([...aliceIdentityPub, ...ikB]);

  return {
    sharedKey,
    ephemeralPublicKey: b64Encode(ekPub),
    associatedData,
    usedOneTimePrekey: usedOPK,
    one_time_prekey_id: bobBundle.one_time_prekey_id ?? null,
  };
}

/**
 * Bob receives Alice's X3DH initiation and derives the same shared key.
 *
 * @param bobIdentityPriv      Bob's X25519 identity private key
 * @param bobIdentityPub       Bob's X25519 identity public key
 * @param bobSignedPrekeyPriv  Bob's SPK private key
 * @param bobOPKPriv           Bob's OPK private key (null if not used)
 * @param aliceEphemeralPub    EK_A from Alice's message header
 * @param aliceIdentityPub     IK_A from Alice's message header
 */
export async function x3dhReceiver(
  bobIdentityPriv: Uint8Array,
  bobIdentityPub: Uint8Array,
  bobSignedPrekeyPriv: Uint8Array,
  bobOPKPriv: Uint8Array | null,
  aliceEphemeralPub: Uint8Array,
  aliceIdentityPub: Uint8Array
): Promise<{ sharedKey: Uint8Array; associatedData: Uint8Array }> {
  // DH1 = DH(SPK_B, IK_A)
  const dh1 = x25519.getSharedSecret(bobSignedPrekeyPriv, aliceIdentityPub);

  // DH2 = DH(IK_B, EK_A)
  const dh2 = x25519.getSharedSecret(bobIdentityPriv, aliceEphemeralPub);

  // DH3 = DH(SPK_B, EK_A)
  const dh3 = x25519.getSharedSecret(bobSignedPrekeyPriv, aliceEphemeralPub);

  let dhInput: Uint8Array;

  if (bobOPKPriv) {
    // DH4 = DH(OPK_B, EK_A)
    const dh4 = x25519.getSharedSecret(bobOPKPriv, aliceEphemeralPub);
    dhInput = new Uint8Array([...dh1, ...dh2, ...dh3, ...dh4]);
  } else {
    dhInput = new Uint8Array([...dh1, ...dh2, ...dh3]);
  }

  const sharedKey = await hkdfDerive(dhInput, X3DH_SALT, HKDF_INFO_X3DH, 32);

  // Associated data must match what Alice computed
  const associatedData = new Uint8Array([...aliceIdentityPub, ...bobIdentityPub]);

  return { sharedKey, associatedData };
}
