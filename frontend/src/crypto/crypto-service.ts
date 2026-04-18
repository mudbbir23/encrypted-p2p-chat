import { x25519 } from "@noble/curves/ed25519";
import { ed25519 } from "@noble/curves/ed25519";
import { KeyStore, IdentityKeys, SignedPrekeyRecord, OneTimePrekeyRecord } from "./key-store";
import { initRatchetReceiver, initRatchetSender, ratchetDecrypt, ratchetEncrypt, RatchetState } from "./double-ratchet";
import { b64Decode, b64Encode, randomBytes } from "./primitives";
import { x3dhReceiver, x3dhSender } from "./x3dh";
import { updateMessageDecrypted, updateMessageError } from "../stores";

export class CryptoService {
  // ---------------------------------------------------------------------------
  // Key Generation
  // ---------------------------------------------------------------------------

  async generateAndStoreIdentityKeys(): Promise<IdentityKeys> {
    const x25519Priv = randomBytes(32);
    const x25519Pub = x25519.getPublicKey(x25519Priv);
    const ed25519Priv = ed25519.utils.randomPrivateKey();
    const ed25519Pub = ed25519.getPublicKey(ed25519Priv);

    const keys: IdentityKeys = {
      x25519_private: b64Encode(x25519Priv),
      x25519_public: b64Encode(x25519Pub),
      ed25519_private: b64Encode(ed25519Priv),
      ed25519_public: b64Encode(ed25519Pub),
    };

    await KeyStore.saveIdentityKeys(keys);
    return keys;
  }

  async generateSignedPrekey(): Promise<{ id: string; public: string; private: string; signature: string }> {
    const identityKeys = await KeyStore.getIdentityKeys();
    if (!identityKeys) throw new Error("Identity keys not found");

    const spkPriv = randomBytes(32);
    const spkPub = x25519.getPublicKey(spkPriv);
    const spkId = crypto.randomUUID();

    const ed25519Priv = b64Decode(identityKeys.ed25519_private);
    const sig = ed25519.sign(spkPub, ed25519Priv);

    const record: SignedPrekeyRecord = {
      id: spkId,
      private: b64Encode(spkPriv),
      public: b64Encode(spkPub),
      created_at: Date.now(),
    };
    await KeyStore.saveSignedPrekey(record);

    return {
      id: spkId,
      public: b64Encode(spkPub),
      private: b64Encode(spkPriv),
      signature: b64Encode(sig),
    };
  }

  async generateOneTimePrekeys(count: number): Promise<Array<{ id: string; public: string; key_id: number }>> {
    const records: OneTimePrekeyRecord[] = [];
    const result: Array<{ id: string; public: string; key_id: number }> = [];

    for (let i = 0; i < count; i++) {
      const priv = randomBytes(32);
      const pub = x25519.getPublicKey(priv);
      const id = crypto.randomUUID();
      const key_id = Date.now() + i;

      records.push({ id, private: b64Encode(priv), public: b64Encode(pub), used: false, key_id });
      result.push({ id, public: b64Encode(pub), key_id });
    }

    await KeyStore.saveOneTimePrekeys(records);
    return result;
  }

  // ---------------------------------------------------------------------------
  // Encrypt
  // ---------------------------------------------------------------------------

  async encrypt(peerId: string, plaintext: string): Promise<any> {
    const keys = await KeyStore.getIdentityKeys();
    if (!keys) throw new Error("Key setup required — identity keys not found");

    let state = (await KeyStore.getRatchetState(peerId)) as RatchetState | undefined;
    let x3dhResult: any = null;

    if (!state) {
      console.log("[Crypto] First message to peer, fetching X3DH bundle...");
      const res = await fetch(`/api/encryption/prekey-bundle/${peerId}`);
      if (!res.ok) throw new Error("Failed to fetch peer prekey bundle");
      const bundle = await res.json();

      const iKPriv = b64Decode(keys.x25519_private);
      const iKPub = b64Decode(keys.x25519_public);

      x3dhResult = await x3dhSender(iKPriv, iKPub, bundle);
      const spkPub = b64Decode(bundle.signed_prekey);

      state = await initRatchetSender(x3dhResult.sharedKey, spkPub, x3dhResult.associatedData);

      // ✅ Store which OPK Alice used (by its public key) so it can go in the first-message header
      if (x3dhResult.usedOneTimePrekey && bundle.one_time_prekey) {
        state = { ...state, opkPubUsed: bundle.one_time_prekey };
      }

      await KeyStore.saveRatchetState(peerId, state);
      console.log("[Crypto] X3DH sender handshake complete. OPK used:", x3dhResult.usedOneTimePrekey);
    }

    const [newState, encMsg] = await ratchetEncrypt(state, plaintext);
    // After first send, clear opkPubUsed — only needed in the first message header
    const stateToSave = { ...newState, opkPubUsed: undefined };
    await KeyStore.saveRatchetState(peerId, stateToSave);

    return {
      ciphertext: encMsg.ciphertext,
      nonce: encMsg.nonce,
      header: JSON.stringify(encMsg.header),
      ephemeralPubKey: x3dhResult?.ephemeralPublicKey ?? undefined,
    };
  }

  // ---------------------------------------------------------------------------
  // Decrypt
  // ---------------------------------------------------------------------------

  async decrypt(
    peerId: string,
    ciphertextB64: string,
    nonceB64: string,
    headerStr: string,
    ephemeralPubKey?: string,
    msgId?: string,
    roomId?: string
  ): Promise<string> {
    const keys = await KeyStore.getIdentityKeys();
    if (!keys) {
      const err = "Encryption keys not set up";
      if (roomId && msgId) updateMessageError(roomId, msgId, err);
      throw new Error(err);
    }

    let state = (await KeyStore.getRatchetState(peerId)) as RatchetState | undefined;

    // If the message contains an ephemeralPubKey → it's a handshake (first message or session reset).
    // ALWAYS re-run X3DH in this case.
    if (ephemeralPubKey) {
      console.log("[Crypto] Handshake detected — running X3DH receiver for peer:", peerId);
      const iKPriv = b64Decode(keys.x25519_private);
      const iKPub = b64Decode(keys.x25519_public);
      const header = JSON.parse(headerStr);

      // Find the right signed prekey
      const spkId = header.spk_id;
      let spkRecord = spkId ? await KeyStore.getSignedPrekey(spkId) : undefined;
      if (!spkRecord) {
        const allSpks = await KeyStore.getAllSignedPrekeys();
        spkRecord = allSpks[allSpks.length - 1];
        if (spkId) console.warn("[Crypto] SPK ID", spkId, "not found, falling back to most recent");
      }
      if (!spkRecord) {
        const err = "No signed prekey found — cannot decrypt";
        if (roomId && msgId) updateMessageError(roomId, msgId, err);
        throw new Error(err);
      }

      const spkPriv = b64Decode(spkRecord.private);
      const spkPub = b64Decode(spkRecord.public);

      // ✅ Look up OPK by public key (the sender stamped opk_pub in the header)
      let opkPriv: Uint8Array | null = null;
      if (header.opk_pub) {
        const opkRecord = await KeyStore.getOPKPrivateKeyByPublic(header.opk_pub);
        if (opkRecord) {
          opkPriv = b64Decode(opkRecord.private);
          await KeyStore.markOPKUsed(opkRecord.id);
          console.log("[Crypto] Found OPK by public key — including DH4 in X3DH.");
        } else {
          console.warn("[Crypto] opk_pub in header but no matching unused OPK found — computing without DH4");
        }
      }

      // Get sender's identity key from header.ik (32-byte Alice IK, after our fix)
      const senderIKPub = header.ik ? b64Decode(header.ik) : b64Decode(ephemeralPubKey);

      const x3dh = await x3dhReceiver(
        iKPriv,
        iKPub,
        spkPriv,
        opkPriv,
        b64Decode(ephemeralPubKey),
        senderIKPub
      );

      state = await initRatchetReceiver(x3dh.sharedKey, spkPriv, spkPub, x3dh.associatedData);
      await KeyStore.saveRatchetState(peerId, state);
      console.log("[Crypto] X3DH receiver complete. Shared key derived.");
    } else if (!state) {
      const err = "No session found — ask the sender to start a new chat";
      if (roomId && msgId) updateMessageError(roomId, msgId, err);
      throw new Error(err);
    }

    try {
      const msg = {
        header: JSON.parse(headerStr),
        ciphertext: ciphertextB64,
        nonce: nonceB64,
      };

      const [newState, plainBytes] = await ratchetDecrypt(state!, msg);
      await KeyStore.saveRatchetState(peerId, newState);
      const plaintext = new TextDecoder().decode(plainBytes);

      // ✅ Update the UI store with the decrypted plaintext
      if (roomId && msgId) {
        updateMessageDecrypted(roomId, msgId, plaintext);
      }
      return plaintext;
    } catch (err: any) {
      console.error("[Crypto] ratchetDecrypt failed:", err?.message ?? err);
      if (roomId && msgId) {
        updateMessageError(roomId, msgId, "Decryption failed: " + (err?.message ?? "OperationError"));
      }
      throw err;
    }
  }
}

export const cryptoService = new CryptoService();
