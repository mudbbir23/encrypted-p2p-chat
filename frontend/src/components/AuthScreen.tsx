/**
 * WebAuthn Authentication Screen.
 * Handles both registration (new user) and login (existing user).
 */
import { createSignal, Show } from "solid-js";
import { setAuth } from "../stores";
import { KeyStore } from "../crypto/key-store";
import { cryptoService } from "../crypto/crypto-service";

type Mode = "login" | "register";

export default function AuthScreen() {
  const [mode, setMode] = createSignal<Mode>("login");
  const [username, setUsername] = createSignal("");
  const [displayName, setDisplayName] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");

  async function handleRegister() {
    setLoading(true);
    setError("");

    try {
      // Step 1: Get registration options from server
      const beginRes = await fetch("/api/auth/register/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username(),
          display_name: displayName() || username(),
        }),
      });

      if (!beginRes.ok) {
        const err = await beginRes.json();
        throw new Error(err.detail || "Registration failed");
      }

      const options = await beginRes.json();

      // Step 2: Call navigator.credentials.create() with the options
      // Convert base64url challenge to Uint8Array
      const challengeBytes = b64ToUint8(options.challenge);
      const userIdBytes = b64ToUint8(options.user.id);

      const publicKey: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: challengeBytes,
        user: {
          ...options.user,
          id: userIdBytes,
        },
        excludeCredentials: (options.excludeCredentials ?? []).map((c: any) => ({
          ...c,
          id: b64ToUint8(c.id),
        })),
      };

      const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential;
      if (!credential) throw new Error("Registration cancelled");

      // Step 3: Send credential to server for verification
      const attestation = credential.response as AuthenticatorAttestationResponse;
      const credentialJSON = {
        id: credential.id,
        rawId: uint8ToB64(new Uint8Array(credential.rawId)),
        type: credential.type,
        response: {
          clientDataJSON: uint8ToB64(new Uint8Array(attestation.clientDataJSON)),
          attestationObject: uint8ToB64(new Uint8Array(attestation.attestationObject)),
        },
      };

      const completeRes = await fetch("/api/auth/register/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username(),
          display_name: displayName() || username(),
          credential: credentialJSON,
        }),
      });

      if (!completeRes.ok) {
        const err = await completeRes.json();
        throw new Error(err.detail || "Registration verification failed");
      }

      const user = await completeRes.json();

      // Step 4: Generate and upload encryption keys
      const ikKeys = await cryptoService.generateAndStoreIdentityKeys();
      const spkKeys = await cryptoService.generateSignedPrekey();
      const opkKeys = await cryptoService.generateOneTimePrekeys(20);

      const keysPayload = {
        identity_key_x25519: ikKeys.x25519_public,
        identity_key_ed25519: ikKeys.ed25519_public,
        signed_prekey: spkKeys.public,
        signed_prekey_sig: spkKeys.signature,
        one_time_prekeys: opkKeys.map((k) => k.public),
      };

      const keyUploadRes = await fetch(`/api/auth/keys/${user.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(keysPayload),
      });

      if (!keyUploadRes.ok) {
        throw new Error("Completed WebAuthn, but uploading encryption keys failed.");
      }

      // Save session to IndexedDB
      await KeyStore.saveSessionInfo({
        user_id: user.id,
        username: user.username,
        display_name: user.display_name,
      });

      setAuth({
        user_id: user.id,
        username: user.username,
        display_name: user.display_name,
      });
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin() {
    setLoading(true);
    setError("");

    try {
      // Step 1: Get authentication options
      const beginRes = await fetch("/api/auth/authenticate/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username() }),
      });

      if (!beginRes.ok) {
        const err = await beginRes.json();
        throw new Error(err.detail || "Authentication failed");
      }

      const options = await beginRes.json();

      // Step 2: Call navigator.credentials.get()
      const publicKey: PublicKeyCredentialRequestOptions = {
        ...options,
        challenge: b64ToUint8(options.challenge),
        allowCredentials: (options.allowCredentials ?? []).map((c: any) => ({
          ...c,
          id: b64ToUint8(c.id),
        })),
      };

      const credential = await navigator.credentials.get({ publicKey }) as PublicKeyCredential;
      if (!credential) throw new Error("Authentication cancelled");

      // Step 3: Send assertion to server
      const assertion = credential.response as AuthenticatorAssertionResponse;
      const credentialJSON = {
        id: credential.id,
        rawId: uint8ToB64(new Uint8Array(credential.rawId)),
        type: credential.type,
        response: {
          clientDataJSON: uint8ToB64(new Uint8Array(assertion.clientDataJSON)),
          authenticatorData: uint8ToB64(new Uint8Array(assertion.authenticatorData)),
          signature: uint8ToB64(new Uint8Array(assertion.signature)),
          userHandle: assertion.userHandle
            ? uint8ToB64(new Uint8Array(assertion.userHandle))
            : null,
        },
      };

      const completeRes = await fetch("/api/auth/authenticate/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username(),
          credential: credentialJSON,
        }),
      });

      if (!completeRes.ok) {
        const err = await completeRes.json();
        throw new Error(err.detail || "Authentication failed");
      }

      const user = await completeRes.json();

      await KeyStore.saveSessionInfo({
        user_id: user.user_id,
        username: user.username,
        display_name: user.display_name,
      });

      setAuth({
        user_id: user.user_id,
        username: user.username,
        display_name: user.display_name,
      });
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }

  const handleSubmit = () => {
    if (mode() === "register") {
      handleRegister();
    } else {
      handleLogin();
    }
  };

  return (
    <div class="auth-screen">
      <div class="auth-card">
        <div class="auth-logo">
          <div class="auth-logo-icon">🔐</div>
          <h1 class="auth-title">E2E Chat</h1>
          <p class="auth-subtitle">
            Signal Protocol encryption · WebAuthn authentication
            <br />
            Zero-knowledge server · No passwords
          </p>
        </div>

        <div class="auth-form">
          <Show when={error()}>
            <div class="error-message">{error()}</div>
          </Show>

          <div class="passkey-info">
            <span class="passkey-icon">🔑</span>
            <span>
              Uses <strong>passkeys</strong> (WebAuthn) — your device biometrics or PIN.
              No passwords stored. Protected by your hardware.
            </span>
          </div>

          <div class="form-group">
            <label class="form-label">Username</label>
            <input
              id="auth-username"
              class="form-input"
              type="text"
              placeholder="Enter your username"
              value={username()}
              onInput={(e) => setUsername(e.currentTarget.value)}
              autocomplete="username"
              disabled={loading()}
            />
          </div>

          <Show when={mode() === "register"}>
            <div class="form-group">
              <label class="form-label">Display Name</label>
              <input
                id="auth-display-name"
                class="form-input"
                type="text"
                placeholder="Your display name"
                value={displayName()}
                onInput={(e) => setDisplayName(e.currentTarget.value)}
                disabled={loading()}
              />
            </div>
          </Show>

          <button
            id="auth-submit-btn"
            class="btn-primary"
            onClick={handleSubmit}
            disabled={loading() || !username()}
          >
            <Show when={loading()}>
              <div class="spinner" />
            </Show>
            <Show when={!loading()}>
              {mode() === "register" ? "🔐 Create Account" : "🔑 Sign In with Passkey"}
            </Show>
          </button>

          <div class="auth-divider">or</div>

          <button
            id="auth-mode-toggle"
            class="btn-secondary"
            onClick={() => {
              setMode(mode() === "login" ? "register" : "login");
              setError("");
            }}
            disabled={loading()}
          >
            {mode() === "login" ? "Create a new account" : "Sign in to existing account"}
          </button>
        </div>
      </div>
    </div>
  );
}

// Helpers
function b64ToUint8(b64: string): Uint8Array {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (padded.length % 4)) % 4;
  return Uint8Array.from(atob(padded + "=".repeat(pad)), (c) => c.charCodeAt(0));
}

function uint8ToB64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
