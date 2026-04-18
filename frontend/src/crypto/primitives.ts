/**
 * Cryptographic primitives using the WebCrypto API.
 */

/** AES-GCM nonce length in bytes (96 bits per NIST recommendation) */
export const AES_GCM_NONCE_BYTES = 12;
export const AES_GCM_KEY_BITS = 256;
export const HKDF_OUTPUT_BYTES = 32;

// ---------------------------------------------------------------------------
// Base64url encoding/decoding
// ---------------------------------------------------------------------------

export function b64Encode(data: Uint8Array | ArrayBuffer): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function b64Decode(data: string | Uint8Array): Uint8Array {
  if (data instanceof Uint8Array) return new Uint8Array(data); // ensure ArrayBuffer backing
  if (!data || typeof data !== "string") return new Uint8Array(0);

  const padded = data.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (padded.length % 4)) % 4;
  const base64 = padded + "=".repeat(padding);
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

// ---------------------------------------------------------------------------
// Ensure an ArrayBuffer-backed Uint8Array (required for WebCrypto on some TS targets)
// ---------------------------------------------------------------------------
function toU8(data: Uint8Array): Uint8Array<ArrayBuffer> {
  if (data.buffer instanceof ArrayBuffer && data.byteOffset === 0 && data.byteLength === data.buffer.byteLength) {
    return data as Uint8Array<ArrayBuffer>;
  }
  // Copy into a plain ArrayBuffer
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy;
}

// ---------------------------------------------------------------------------
// Timing-safe comparison
// ---------------------------------------------------------------------------

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Random bytes
// ---------------------------------------------------------------------------

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

// ---------------------------------------------------------------------------
// HKDF key derivation
// ---------------------------------------------------------------------------

export async function hkdfDerive(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  outputLength: number = HKDF_OUTPUT_BYTES
): Promise<Uint8Array> {
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    toU8(ikm),
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toU8(salt),
      info: new TextEncoder().encode(info),
    },
    ikmKey,
    outputLength * 8
  );

  return new Uint8Array(derived);
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

export async function importAESKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toU8(rawKey),
    { name: "AES-GCM", length: AES_GCM_KEY_BITS },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const nonce = randomBytes(AES_GCM_NONCE_BYTES);

  const params: AesGcmParams = { name: "AES-GCM", iv: toU8(nonce) };
  if (additionalData) {
    params.additionalData = toU8(additionalData);
  }

  const encrypted = await crypto.subtle.encrypt(params, key, toU8(plaintext));

  return {
    nonce,
    ciphertext: new Uint8Array(encrypted),
  };
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const params: AesGcmParams = { name: "AES-GCM", iv: toU8(nonce) };
  if (additionalData) {
    params.additionalData = toU8(additionalData);
  }

  const decrypted = await crypto.subtle.decrypt(params, key, toU8(ciphertext));
  return new Uint8Array(decrypted);
}

// ---------------------------------------------------------------------------
// HMAC-SHA-256
// ---------------------------------------------------------------------------

export async function hmacSha256(
  keyBytes: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    toU8(keyBytes),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const tag = await crypto.subtle.sign("HMAC", key, toU8(data));
  return new Uint8Array(tag);
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
