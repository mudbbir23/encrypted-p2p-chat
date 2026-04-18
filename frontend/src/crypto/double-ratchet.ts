import { x25519 } from "@noble/curves/ed25519";
import { aesGcmDecrypt, aesGcmEncrypt, b64Decode, b64Encode, hkdfDerive, importAESKey, randomBytes } from "./primitives";

export interface RatchetState {
  rootKey: string;
  sendChainKey?: string;
  recvChainKey?: string;
  dhSendPriv?: string;
  dhSendPub?: string;
  dhRecvPub: string | null;
  sendCount: number;
  recvCount: number;
  skippedKeys: Record<string, Record<number, string>>;
  associatedData: string;
  /** OPK public key Alice used (base64url). Present only in sender state for first message. */
  opkPubUsed?: string;
}

const MAX_SKIP = 100;
const RATCHET_RK_INFO = "ratchet-rk";

// ---------------------------------------------------------------------------
// KDF_RK: advance the root key with a new DH output
// ---------------------------------------------------------------------------
async function kdfRK(rk: Uint8Array, dhOut: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  const info = new TextEncoder().encode(RATCHET_RK_INFO);
  // Use dhOut as the IKM (input key material) and rk as the salt per Signal spec
  const derived = await hkdfDerive(dhOut, rk, RATCHET_RK_INFO, 64);
  return [derived.slice(0, 32), derived.slice(32, 64)];
}

// ---------------------------------------------------------------------------
// KDF_CK: advance the chain key to produce a message key
// Uses HMAC-SHA-256 via WebCrypto importKey + sign
// ---------------------------------------------------------------------------
async function kdfCK(ck: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  // Copy into a plain ArrayBuffer to satisfy WebCrypto strict typing
  const ckBuf = new Uint8Array(ck.byteLength);
  ckBuf.set(ck);

  const key = await crypto.subtle.importKey(
    "raw",
    ckBuf,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const msgKeyBuf = await crypto.subtle.sign("HMAC", key, new Uint8Array([0x01]));
  const nextCKBuf = await crypto.subtle.sign("HMAC", key, new Uint8Array([0x02]));

  return [new Uint8Array(msgKeyBuf), new Uint8Array(nextCKBuf)];
}

// ---------------------------------------------------------------------------
// Initialise ratchet as SENDER (Alice)
// ---------------------------------------------------------------------------
export async function initRatchetSender(
  sharedKey: Uint8Array,
  bobSignedPrekeyPub: Uint8Array,
  associatedData: Uint8Array
): Promise<RatchetState> {
  // Generate a fresh DH ratchet keypair
  const dhSendPriv = randomBytes(32);
  const dhSendPub = x25519.getPublicKey(dhSendPriv);

  // Alice performs the first ratchet step so she can start sending immediately
  const dhOut = x25519.getSharedSecret(dhSendPriv, bobSignedPrekeyPub);
  const [newRootKey, sendCK] = await kdfRK(sharedKey, dhOut);

  return {
    rootKey: b64Encode(newRootKey),
    sendChainKey: b64Encode(sendCK),
    dhSendPriv: b64Encode(dhSendPriv),
    dhSendPub: b64Encode(dhSendPub),
    dhRecvPub: b64Encode(bobSignedPrekeyPub),
    sendCount: 0,
    recvCount: 0,
    skippedKeys: {},
    associatedData: b64Encode(associatedData),
  };
}

// ---------------------------------------------------------------------------
// Initialise ratchet as RECEIVER (Bob)
// ---------------------------------------------------------------------------
export async function initRatchetReceiver(
  sharedKey: Uint8Array,
  bobSignedPrekeyPriv: Uint8Array,
  bobSignedPrekeyPub: Uint8Array,
  associatedData: Uint8Array
): Promise<RatchetState> {
  // Bob starts with the raw sharedKey as root key.
  // The first DH ratchet step happens when Alice's message arrives.
  return {
    rootKey: b64Encode(sharedKey),
    dhSendPriv: b64Encode(bobSignedPrekeyPriv),
    dhSendPub: b64Encode(bobSignedPrekeyPub),
    dhRecvPub: null, // Not yet known — will be set on first decrypt
    sendCount: 0,
    recvCount: 0,
    skippedKeys: {},
    associatedData: b64Encode(associatedData),
  };
}

// ---------------------------------------------------------------------------
// Encrypt a plaintext message
// ---------------------------------------------------------------------------
export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: string
): Promise<[RatchetState, any]> {
  if (!state.sendChainKey) throw new Error("Send chain key missing — ratchet not initialised for sending");

  const ck = b64Decode(state.sendChainKey);
  const [msgKeyBytes, newCKBytes] = await kdfCK(ck);
  const ad = b64Decode(state.associatedData);

  // Import raw message key as AES-GCM CryptoKey
  const msgKey = await importAESKey(msgKeyBytes);
  const { nonce, ciphertext } = await aesGcmEncrypt(msgKey, new TextEncoder().encode(plaintext), ad);

  // AD = AliceIK (32 bytes) || BobIK (32 bytes) per X3DH spec
  // Send only Alice's 32-byte identity key so Bob can rerun x3dhReceiver correctly
  const aliceIKPub = ad.slice(0, 32);

  const header: Record<string, unknown> = {
    dh: state.dhSendPub,       // Current ratchet public key
    pn: state.sendCount,       // Messages sent in previous chain
    n: state.sendCount,        // Message index in current chain
    ik: b64Encode(aliceIKPub), // Alice's real 32-byte identity key
  };
  // On the first message, tell Bob which OPK Alice used in X3DH (so he can compute DH4)
  if (state.opkPubUsed) {
    header.opk_pub = state.opkPubUsed;
  }

  const newState: RatchetState = {
    ...state,
    sendChainKey: b64Encode(newCKBytes),
    sendCount: state.sendCount + 1,
  };

  return [newState, { nonce: b64Encode(nonce), ciphertext: b64Encode(ciphertext), header }];
}

// ---------------------------------------------------------------------------
// Decrypt an incoming message
// ---------------------------------------------------------------------------
export async function ratchetDecrypt(
  state: RatchetState,
  msg: { header: any; ciphertext: string; nonce: string }
): Promise<[RatchetState, Uint8Array]> {
  const header = msg.header;
  let newState = { ...state, skippedKeys: { ...state.skippedKeys } };

  // Check if we already stored this message key (out-of-order delivery)
  const pubB64 = header.dh as string;
  if (newState.skippedKeys[pubB64]?.[header.n] !== undefined) {
    const keyBytes = b64Decode(newState.skippedKeys[pubB64][header.n]);
    const skippedCopy = { ...newState.skippedKeys };
    const chainCopy = { ...skippedCopy[pubB64] };
    delete chainCopy[header.n];
    skippedCopy[pubB64] = chainCopy;
    newState = { ...newState, skippedKeys: skippedCopy };
    const plain = await decryptWithKey(keyBytes, msg, b64Decode(state.associatedData));
    return [newState, plain];
  }

  // If header.dh is different from dhRecvPub, the sender ratcheted — we must too
  if (header.dh !== newState.dhRecvPub) {
    // Store skipped keys from the previous receiving chain
    newState = await skipMessageKeys(newState, header.pn ?? 0);
    // Perform the DH ratchet step
    newState = await dhRatchetStep(newState, header.dh);
  }

  // Skip any missing messages in the current receiving chain
  newState = await skipMessageKeys(newState, header.n);

  // Advance chain key one more step to get the message key
  const ck = b64Decode(newState.recvChainKey!);
  const [msgKeyBytes, newCKBytes] = await kdfCK(ck);

  newState = {
    ...newState,
    recvChainKey: b64Encode(newCKBytes),
    recvCount: newState.recvCount + 1,
  };

  const plain = await decryptWithKey(msgKeyBytes, msg, b64Decode(state.associatedData));
  return [newState, plain];
}

// ---------------------------------------------------------------------------
// Skip message keys (out-of-order support)
// ---------------------------------------------------------------------------
async function skipMessageKeys(state: RatchetState, until: number): Promise<RatchetState> {
  if (state.recvCount >= until) return state;
  if (until - state.recvCount > MAX_SKIP) throw new Error("Too many skipped messages");
  if (!state.recvChainKey) return state;

  let newState = { ...state, skippedKeys: { ...state.skippedKeys } };
  let ck = b64Decode(newState.recvChainKey!);
  const pubB64 = newState.dhRecvPub ?? "__unknown__";

  while (newState.recvCount < until) {
    const [msgKeyBytes, nextCKBytes] = await kdfCK(ck);
    const chainKeys = { ...(newState.skippedKeys[pubB64] ?? {}) };
    chainKeys[newState.recvCount] = b64Encode(msgKeyBytes);
    newState = {
      ...newState,
      skippedKeys: { ...newState.skippedKeys, [pubB64]: chainKeys },
      recvCount: newState.recvCount + 1,
    };
    ck = nextCKBytes;
  }

  return { ...newState, recvChainKey: b64Encode(ck) };
}

// ---------------------------------------------------------------------------
// Diffie-Hellman ratchet step
// ---------------------------------------------------------------------------
async function dhRatchetStep(state: RatchetState, newDHPubKey: string): Promise<RatchetState> {
  const rk = b64Decode(state.rootKey);

  // Step 1: Derive recv chain key using sender's new ratchet public key
  const dhIn = x25519.getSharedSecret(b64Decode(state.dhSendPriv!), b64Decode(newDHPubKey));
  const [rk1, recvCK] = await kdfRK(rk, dhIn);

  // Step 2: Generate our new ratchet keypair and derive send chain key
  const newSendPriv = randomBytes(32);
  const newSendPub = x25519.getPublicKey(newSendPriv);
  const dhOut = x25519.getSharedSecret(newSendPriv, b64Decode(newDHPubKey));
  const [rk2, sendCK] = await kdfRK(rk1, dhOut);

  return {
    ...state,
    rootKey: b64Encode(rk2),
    sendChainKey: b64Encode(sendCK),
    recvChainKey: b64Encode(recvCK),
    dhSendPriv: b64Encode(newSendPriv),
    dhSendPub: b64Encode(newSendPub),
    dhRecvPub: newDHPubKey,
    sendCount: 0,
    recvCount: 0,
  };
}

// ---------------------------------------------------------------------------
// Decrypt with a raw message key (Uint8Array → CryptoKey → AES-GCM decrypt)
// ---------------------------------------------------------------------------
async function decryptWithKey(
  keyBytes: Uint8Array,
  msg: { ciphertext: string; nonce: string },
  ad: Uint8Array
): Promise<Uint8Array> {
  try {
    const key = await importAESKey(keyBytes);
    return await aesGcmDecrypt(key, b64Decode(msg.nonce), b64Decode(msg.ciphertext), ad);
  } catch (e) {
    console.error(
      "[DoubleRatchet] Decrypt failed.",
      "nonce len:", b64Decode(msg.nonce).length,
      "ct len:", b64Decode(msg.ciphertext).length,
      "ad len:", ad.length
    );
    throw e;
  }
}
