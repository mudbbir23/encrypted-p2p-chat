/**
 * IndexedDB-backed key store for Signal Protocol key material.
 *
 * This is the browser's secure equivalent of the server's PostgreSQL models.
 * All private key material lives ONLY here — never sent to the server.
 *
 * Database name: e2e_chat_keys
 * Object stores:
 *   - identity_keys: {id: 'local', x25519_private, x25519_public, ed25519_private, ed25519_public}
 *   - signed_prekeys: {id: spk_id, private, public, created_at}
 *   - one_time_prekeys: {id: opk_id, private, public, used: bool}
 *   - ratchet_states: {id: peer_user_id, state: DoubleRatchetState (JSON)}
 *   - session_info: {id: 'auth', user_id, username}
 *
 * Security notes:
 * - Keys are stored as base64url strings (CryptoKey objects are not serializable)
 * - In production, consider using CryptoKey exports with PBKDF2-derived wrapping keys
 *   so private keys are encrypted at rest in IndexedDB.
 */

const DB_NAME = "e2e_chat_keys";
const DB_VERSION = 1;

export interface IdentityKeys {
  x25519_private: string;  // base64url X25519 private key
  x25519_public: string;   // base64url X25519 public key
  ed25519_private: string; // base64url Ed25519 private key
  ed25519_public: string;  // base64url Ed25519 public key
}

export interface SignedPrekeyRecord {
  id: string;
  private: string;
  public: string;
  created_at: number;
}

export interface OneTimePrekeyRecord {
  id: string;
  private: string;
  public: string;
  used: boolean;
  key_id: number;
}

export interface SessionInfo {
  user_id: string;
  username: string;
  display_name: string;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      if (!db.objectStoreNames.contains("identity_keys")) {
        db.createObjectStore("identity_keys");
      }
      if (!db.objectStoreNames.contains("signed_prekeys")) {
        db.createObjectStore("signed_prekeys", { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains("one_time_prekeys")) {
        db.createObjectStore("one_time_prekeys", { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains("ratchet_states")) {
        db.createObjectStore("ratchet_states");
      }
      if (!db.objectStoreNames.contains("session_info")) {
        db.createObjectStore("session_info");
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbGetAll<T>(db: IDBDatabase, storeName: string): Promise<T[]> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const store = tx.objectStore(storeName);
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result as T[]);
    req.onerror = () => reject(req.error);
  });
}

function idbGet<T>(db: IDBDatabase, storeName: string, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const store = tx.objectStore(storeName);
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db: IDBDatabase, storeName: string, value: unknown, key?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const req = key !== undefined ? store.put(value, key) : store.put(value);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

function idbDelete(db: IDBDatabase, storeName: string, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const req = store.delete(key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

// ---------------------------------------------------------------------------
// Key Store API
// ---------------------------------------------------------------------------

export const KeyStore = {
  // -------------------------------------------------------------------------
  // Identity Keys
  // -------------------------------------------------------------------------

  async saveIdentityKeys(keys: IdentityKeys): Promise<void> {
    const db = await openDB();
    await idbPut(db, "identity_keys", keys, "local");
    db.close();
  },

  async getIdentityKeys(): Promise<IdentityKeys | undefined> {
    const db = await openDB();
    const keys = await idbGet<IdentityKeys>(db, "identity_keys", "local");
    db.close();
    return keys;
  },

  // -------------------------------------------------------------------------
  // Signed Prekeys
  // -------------------------------------------------------------------------

  async saveSignedPrekey(record: SignedPrekeyRecord): Promise<void> {
    const db = await openDB();
    await idbPut(db, "signed_prekeys", record);
    db.close();
  },

  async getSignedPrekey(id: string): Promise<SignedPrekeyRecord | undefined> {
    const db = await openDB();
    const record = await idbGet<SignedPrekeyRecord>(db, "signed_prekeys", id);
    db.close();
    return record;
  },

  async getAllSignedPrekeys(): Promise<SignedPrekeyRecord[]> {
    const db = await openDB();
    const all = await idbGetAll<SignedPrekeyRecord>(db, "signed_prekeys");
    db.close();
    return all;
  },

  // -------------------------------------------------------------------------
  // One-Time Prekeys
  // -------------------------------------------------------------------------

  async saveOneTimePrekeys(records: OneTimePrekeyRecord[]): Promise<void> {
    const db = await openDB();
    for (const rec of records) {
      await idbPut(db, "one_time_prekeys", rec);
    }
    db.close();
  },

  async getUnusedOPKCount(): Promise<number> {
    const db = await openDB();
    const all = await idbGetAll<OneTimePrekeyRecord>(db, "one_time_prekeys");
    db.close();
    return all.filter((r) => !r.used).length;
  },

  async markOPKUsed(id: string): Promise<void> {
    const db = await openDB();
    const record = await idbGet<OneTimePrekeyRecord>(db, "one_time_prekeys", id);
    if (record) {
      record.used = true;
      await idbPut(db, "one_time_prekeys", record);
    }
    db.close();
  },

  async getOPKPrivateKey(id: string): Promise<string | undefined> {
    const db = await openDB();
    const rec = await idbGet<OneTimePrekeyRecord>(db, "one_time_prekeys", id);
    db.close();
    return rec?.private;
  },

  /** Find an unused OPK private key by matching its public key (base64url). */
  async getOPKPrivateKeyByPublic(publicKeyB64: string): Promise<{ id: string; private: string } | undefined> {
    const db = await openDB();
    const all = await idbGetAll<OneTimePrekeyRecord>(db, "one_time_prekeys");
    db.close();
    const match = all.find((r) => !r.used && r.public === publicKeyB64);
    return match ? { id: match.id, private: match.private } : undefined;
  },

  // -------------------------------------------------------------------------
  // Ratchet States
  // -------------------------------------------------------------------------

  async saveRatchetState(peerId: string, state: object): Promise<void> {
    const db = await openDB();
    await idbPut(db, "ratchet_states", JSON.stringify(state), peerId);
    db.close();
  },

  async getRatchetState(peerId: string): Promise<object | undefined> {
    const db = await openDB();
    const raw = await idbGet<string>(db, "ratchet_states", peerId);
    db.close();
    if (!raw) return undefined;
    try {
      return JSON.parse(raw);
    } catch {
      return undefined;
    }
  },

  // -------------------------------------------------------------------------
  // Session Info
  // -------------------------------------------------------------------------

  async saveSessionInfo(info: SessionInfo): Promise<void> {
    const db = await openDB();
    await idbPut(db, "session_info", info, "auth");
    db.close();
  },

  async getSessionInfo(): Promise<SessionInfo | undefined> {
    const db = await openDB();
    const info = await idbGet<SessionInfo>(db, "session_info", "auth");
    db.close();
    return info;
  },

  async clearSessionInfo(): Promise<void> {
    const db = await openDB();
    await idbDelete(db, "session_info", "auth");
    db.close();
  },

  // -------------------------------------------------------------------------
  // Full wipe (logout)
  // -------------------------------------------------------------------------

  async clearAll(): Promise<void> {
    // Delete the entire IndexedDB database
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  },
};
