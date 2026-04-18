![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)
![Security: Signal Protocol](https://img.shields.io/badge/Security-Signal_Protocol-blue.svg)
![Auth: Passkeys](https://img.shields.io/badge/Auth-Passkeys_(WebAuthn)-green.svg)
![CI Status](https://github.com/mudbbir23/encrypted-p2p-chat/actions/workflows/ci.yml/badge.svg)
![Backend: FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)
![Frontend: SolidJS](https://img.shields.io/badge/Frontend-SolidJS-446B9E.svg)

![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)
![Security: Signal Protocol](https://img.shields.io/badge/Security-Signal_Protocol-blue.svg)
![Auth: Passkeys](https://img.shields.io/badge/Auth-Passkeys_(WebAuthn)-green.svg)
![Backend: FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)
![Frontend: SolidJS](https://img.shields.io/badge/Frontend-SolidJS-446B9E.svg)
![E2EE: Zero Knowledge](https://img.shields.io/badge/E2EE-Zero_Knowledge-blueviolet.svg)

A production-ready, end-to-end encrypted peer-to-peer chat application implementing the **Signal Protocol** (X3DH + Double Ratchet) with **WebAuthn Passkey** authentication. The server is fully zero-knowledge — it only routes ciphertext and never sees plaintext messages or private keys.

---

- 🔐 **End-to-end encryption** — Signal Protocol (X3DH + Double Ratchet)
- 🔑 **Passkey / WebAuthn authentication** — no passwords, phishing-resistant
- 🫥 **Zero-knowledge server** — server only sees ciphertext, never plaintext
- ⚡ **Real-time messaging** — WebSocket-based live delivery
- 🔁 **Forward secrecy** — per-message encryption keys, ratcheting after every exchange
- 🩹 **Post-compromise security** — self-healing sessions after key exposure
- 🗝️ **One-time prekeys (OPK)** — 4-DH X3DH for maximum asynchronous security
- 💾 **Client-side key storage** — all private keys in browser IndexedDB, never uploaded
- 🧪 **Comprehensive Testing** — 100% verified crypto primitives and handshake logic

![E2E Chat Screenshot](https://raw.githubusercontent.com/mudbbir23/encrypted-p2p-chat/master/assets/screenshot.png)

---

## 🔐 Cryptographic Architecture

```
Alice                           Server                           Bob
  |                               |                               |
  |── GET /prekey-bundle/bob ────>|                               |
  |<── { IK_B, SPK_B, OPK_B } ──|                               |
  |                               |                               |
  | X3DH:                         |                               |
  | DH1 = DH(IK_A, SPK_B)        |                               |
  | DH2 = DH(EK_A, IK_B)         |                               |
  | DH3 = DH(EK_A, SPK_B)        |                               |
  | DH4 = DH(EK_A, OPK_B)        |                               |
  | SK  = HKDF(DH1‖DH2‖DH3‖DH4) |                               |
  |                               |                               |
  |── Encrypt(SK, msg) ─────────>|── WebSocket ─────────────────>|
  |   { ciphertext, nonce,        |   (ciphertext only)           | X3DH Receiver
  |     header, EK_A_pub }        |                               | → same SK
  |                               |                               | → Decrypt ✅
```

**Double Ratchet** advances keys after every message:
- **Symmetric ratchet** (KDF chain) → forward secrecy within a session
- **DH ratchet** → break-in recovery after key compromise

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | SolidJS + TypeScript |
| **Styling** | Vanilla CSS |
| **State** | Nanostores |
| **Crypto** | WebCrypto API + `@noble/curves` (X25519, Ed25519) |
| **Key Storage** | Browser IndexedDB |
| **Backend** | FastAPI (Python 3.13+) |
| **Database** | SQLite (dev) / PostgreSQL (prod) |
| **Real-time** | WebSockets |
| **Auth** | WebAuthn / FIDO2 Passkeys |

---

## 🚀 Quick Start (Local Development)

### Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.11+ |
| Node.js | 18+ |
| npm | 9+ |

### 1. Clone the repo

```bash
git clone https://github.com/mudbbir23/encrypted-p2p-chat.git
cd encrypted-p2p-chat
```

### 2. Backend setup

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Start the server (auto-creates SQLite DB on first run)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Backend runs at **http://localhost:8000**  
API docs at **http://localhost:8000/docs**

### 3. Frontend setup

Open a **new terminal**:

```bash
cd frontend

# Install dependencies
npm install

# Start the dev server
npm run dev
```

Frontend runs at **http://localhost:5173**

> Vite proxies `/api` and WebSocket requests to the backend automatically.

### 4. Test the chat

1. Open **two browser tabs** at [http://localhost:5173](http://localhost:5173)
2. Register two different users (e.g. `alice` and `bob`)
3. Start a chat from Alice's tab — type Bob's username and click **Chat**
4. Send a message → Bob's tab receives it **decrypted in plaintext** ✅

---

## 🧪 Testing

The project includes an extensive automated testing suite for both the frontend cryptographic engine and the backend API logic.

### Frontend (Vitest)
Tests verify Base64url encoding, HKDF derivation, constant-time equality, and the full X3DH Alice-to-Bob key agreement.
```bash
cd frontend
npm run test
```

### Backend (Pytest)
Tests verify the cryptographic primitives used by the server for signature verification and bundle management.
```bash
cd backend
python -m pytest tests/test_crypto.py
```

### CI/CD
All tests are automatically executed on every Push or Pull Request via **GitHub Actions** to ensure the `master` branch remains stable.

---

## 🐳 Docker (Full Stack)

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env — change all passwords and SECRET_KEY

# Start everything
docker-compose up -d
```

App available at **http://localhost** (via Nginx reverse proxy).

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and set:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | 64-char hex secret — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `RP_ID` | WebAuthn relying party ID — `localhost` for local dev, your domain for production |
| `RP_ORIGIN` | Exact frontend origin — `http://localhost:5173` for local dev |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated) |
| `DEBUG` | Set `false` in production |

---

## 📂 Project Structure

```
encrypted-p2p-chat/
├── backend/
│   ├── app/
│   │   ├── api/           # FastAPI routers (auth, encryption, ws)
│   │   ├── models/        # SQLModel database models
│   │   ├── schemas/       # Pydantic request/response schemas
│   │   └── services/      # Business logic (auth, prekey, message)
│   └── pyproject.toml
├── frontend/
│   └── src/
│       ├── crypto/        # ← All E2EE logic lives here
│       │   ├── primitives.ts      # WebCrypto: AES-GCM, HKDF, HMAC
│       │   ├── x3dh.ts            # X3DH key agreement
│       │   ├── double-ratchet.ts  # Double Ratchet algorithm
│       │   ├── crypto-service.ts  # High-level encrypt/decrypt API
│       │   └── key-store.ts       # IndexedDB key persistence
│       ├── components/    # SolidJS UI components
│       ├── stores/        # Nanostores (auth, messages, rooms)
│       └── ws/            # WebSocket client
├── nginx/                 # Reverse proxy config
├── docker-compose.yml
└── .env.example
```

---

## 🔒 Security Notes

- **Private keys never leave the device** — all crypto runs in the browser; the server stores only public keys
- **Passkey authentication** — WebAuthn binds credentials to the origin, defeating phishing
- **One-time prekeys** — consumed on first use; server enforces single-use guarantee
- **No plaintext logs** — the backend has no access to message content
- **Session repair** — if a user clears local storage, the next handshake (ephemeral key in header) automatically resets the session

---

## 🐛 Known Issues & History

See the [GitHub Issues](https://github.com/mudbbir23/encrypted-p2p-chat/issues) tab for all tracked bugs and their fixes.

Major bugs resolved in this release:

| # | Bug | Impact |
|---|-----|--------|
| 1 | Wrong import path (`../store` → `../stores`) | `updateMessageDecrypted` was `undefined` — messages never shown decrypted |
| 2 | `kdfCK` used `aesGcmEncrypt` instead of HMAC-SHA-256 | Every message key was derived incorrectly → `OperationError` on decrypt |
| 3 | `header.ik` sent full 64-byte AD instead of 32-byte identity key | Bob's X3DH used wrong `aliceIdentityPub` → completely different shared key |
| 4 | OPK `DH4` computed by Alice but skipped by Bob | Shared key mismatch when a one-time prekey was available on server |
| 5 | Bundle endpoint URL wrong (`/api/crypto/bundle` → `/api/encryption/prekey-bundle`) | Every first message threw "Failed to fetch peer prekey bundle" |
| 6 | Dev fallback silently encoded plaintext as base64 and sent it | Receiver saw garbage "ciphertext" even when crypto failed — hid real errors |

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for details.

---

## 👤 Author

**Mudabbir** — [@mudbbir23](https://github.com/mudbbir23)
