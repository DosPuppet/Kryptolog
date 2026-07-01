# TrustKeys - Post-Quantum Cryptography (PQC) Extension

TrustKeys is a quantum-resistant browser extension designed to secure interactions against future quantum computing threats. It implements the **Module-Lattice-based Key Encapsulation Mechanism (ML-KEM)** and **Digital Signature Algorithm (ML-DSA)** standards.

> **Status**: Beta (Production Functional)
> **Algorithms**: ML-KEM-768 (FIPS 203) & ML-DSA-44 (FIPS 204)
> **Role**: Primary PQC Authentication Provider for Kryptolog.

---

## Architecture & Security

### 1. Quantum-Proof Algorithms
TrustKeys utilizes the NIST multi-round selected algorithms for post-quantum security:
- **Encryption**: ML-KEM-768 (FIPS 203) via `@noble/post-quantum`
  - Used for securely establishing shared secrets (Key Encapsulation).
  - Hybrid Encryption: ML-KEM produces a shared secret, which is run through
    **HKDF-SHA-256** (with a fixed context label) to derive the **AES-256-GCM**
    key that encrypts the message/session payload.
- **Signing**: ML-DSA-44 (FIPS 204) via `@noble/post-quantum`
  - Used for generating unforgeable digital signatures.

These primitives are not implemented in the extension directly: they live in the
shared **`@kryptolog/crypto-core`** package (see below), which the extension and the
Kryptolog web app both consume so their wire/storage formats stay byte-identical.

### Shared crypto core (`@kryptolog/crypto-core`)
All client-side crypto (ML-KEM/ML-DSA, hybrid encryption, session-key wrapping, the
AES-GCM vault, domain separation) lives in **one** versioned package at
[`../packages/crypto-core`](../packages/crypto-core), consumed by both this extension
and the web app via a `file:` dependency. This replaced the two formerly duplicated
`crypto.js` copies and their hand-maintained "KEEP IN SYNC" comment.

`src/utils/crypto.js` is now a thin shim that `export *`s from the package and adds
only extension-local glue — `generateAccount()`, whose account `id` is a random UUID
(the web app instead uses the ML-DSA public key as its id). Because there is a single
source, byte-compatibility between the two builds is **structural** and enforced by the
package's `test/byte-compat.test.js` (golden formats, round-trips, an ML-DSA FIPS-204
server-interop guard, and a `CRYPTO_CORE_VERSION` check) rather than by a comment.

### 2. The Secure Vault
- **Zero-Knowledge Architecture**: Your private keys never leave the extension.
- **Encryption**: The vault is encrypted at rest using **AES-GCM (256-bit)**.
- **Key Derivation**: Your password derives the encryption key using **PBKDF2** (SHA-512, 600,000 iterations).
- **Memory-Only Decryption**: Private keys are decrypted into memory *only* when the vault is unlocked.
- **Session Persistence**: The vault remains unlocked for **1 Hour** of inactivity, via a session secret in `chrome.storage.session` (in-memory), which is **automatically wiped** when the browser is closed.

### 3. Authorization Model
TrustKeys enforces a strict "user consent, least-privilege" model similar to a wallet:
- **No standing host access.** The extension ships with **no** host permissions. It
  requests access to a site **per-origin, under a user gesture** (`chrome.permissions.request`)
  only when you authorize that site, and **revokes** it when you remove the site. So the
  extension only ever holds access to the exact sites you approved.
- **HTTPS-only** for production origins (only `localhost`/`127.0.0.1` may be plain http,
  as dev defaults). A plain-http site cannot be trusted.
- **Explicit consent**: authorizing a site shows its full origin and a clear warning that the
  site will be able to request signatures/decryptions with your keys.
- **Per-operation approval**: every private-key use (sign / decrypt / unwrap) triggers an
  approval popup — **except** silent chat-message signing, which is an **opt-in per-site
  capability** (default OFF). Even when enabled it can only produce `message`-domain
  signatures (never a login, multisig, or document signature).
- **Trusted Sites Management**: authorized origins are stored in the encrypted vault, shown
  in Settings, and can be added/removed (with their host permission and capabilities). The
  trust list is reconciled on startup against actually-granted permissions.
- **Dynamic Content Script Injection**: once a site is authorized (and its host permission
  granted), TrustKeys registers content scripts via `chrome.scripting.registerContentScripts()`.
  The page reloads and `window.trustkeys` becomes available at `document_start`.

---

## Getting Started

### Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   cd trustkeys
   npm install
   ```
3. Build the extension:
   ```bash
   npm run build
   ```
4. Load into Chrome/Brave/Edge:
   - Go to `chrome://extensions`
   - Enable **Developer Mode**
   - Click **Load Unpacked**
   - Select the `trustkeys/dist` folder.

### First-Time Setup
1. **Create Vault**: Click the extension icon. You will be prompted to create a password on first run.
2. **Dashboard**: Once unlocked, you can view your **ML-KEM** and **ML-DSA** public keys.
3. **Account Management**: You can generate multiple PQC accounts inside the vault.

### Authorizing a Website
1. Navigate to the website you want to use TrustKeys with.
2. Click the TrustKeys extension icon.
3. The popup shows the current tab's origin with an **Authorize** button.
4. Click **Authorize** — the tab reloads and `window.trustkeys` is now available.
5. The site can then call `connect()` to request access to your keys.

Alternatively, add sites manually from **Settings > Manage Trusted Sites**.

### Configuration
You can configure the backend API URL in the Settings menu:
1. Open Extension > Settings.
2. Click **Config (API)**.
3. **API URL**: The backend server URL (Default: `http://localhost:8000`).

---

## Web API Reference

TrustKeys injects a `window.trustkeys` object into authorized web pages.

> **Note**: `window.trustkeys` is only available on sites the user has explicitly authorized. On unauthorized sites, the object does not exist. See [Authorizing a Website](#authorizing-a-website) above.

### Detection & Connection

#### `handshake()`
Detect the extension and get its ID.
```javascript
const extensionId = await window.trustkeys.handshake();
```

#### `connect()`
Request access to the user's wallet. **Required** before any other method.
```javascript
const success = await window.trustkeys.connect();
// Triggers popup. Returns true if approved.
```

#### `isConnected()`
Check if the current site is connected (without triggering a popup).
```javascript
const connected = await window.trustkeys.isConnected();
// Returns boolean.
```

### Account

#### `getAccount()`
Get the active account's public keys.
```javascript
const account = await window.trustkeys.getAccount();
// Returns {
//   name: "My PQC Key",
//   kyberPublicKey: "hex...",
//   dilithiumPublicKey: "hex..."
// }
```

### Digital Signatures (ML-DSA)

#### `sign(message)`
Sign a message using the active account's ML-DSA-44 private key.
```javascript
const signature = await window.trustkeys.sign("Login Nonce: 12345");
// Triggers Approval Popup. Returns hex-encoded signature.
```

#### `verify(message, signature, publicKey)`
Verify an ML-DSA-44 signature against a public key.
```javascript
const valid = await window.trustkeys.verify(message, signature, publicKey);
// Returns boolean.
```

#### `signMessage(message)`
Sign a **chat message** with the active account's ML-DSA-44 key. Unlike `sign()`,
this can sign **without** a per-message popup — but only for payloads in the
`message` domain (the call is refused otherwise), and only if the user enabled
"Allow silent message signing" for the site (default off; dev origins always
allowed). For sites without that capability it falls back to a per-message
approval popup.
```javascript
const signature = await window.trustkeys.signMessage(messageDomainPayload);
// Returns hex-encoded signature. (Used by the messenger to authenticate messages.)
```

### Encryption (ML-KEM + AES)

#### `encrypt(message, [publicKey])`
Encrypt data. If `publicKey` is omitted, encrypts for the active account (self).
```javascript
const encrypted = await window.trustkeys.encrypt("My Secret", recipientKyberKey);
// Returns ciphertext object.
```

#### `decrypt(ciphertext)`
Decrypt data intended for the active user.
```javascript
const plaintext = await window.trustkeys.decrypt(encryptedObject);
// Triggers Approval Popup. Returns original string.
```

### Session Key Management (E2EE)
Helpers for managing symmetric session keys (AES-256) used in end-to-end encrypted messaging.

#### `generateSessionKey()`
```javascript
const key = await window.trustkeys.generateSessionKey();
// Returns 32-byte AES key (hex).
```

#### `wrapSessionKey(sessionKey, publicKey)`
Encrypt a session key for a specific recipient using their Kyber public key.
```javascript
const wrapped = await window.trustkeys.wrapSessionKey(sessionKey, recipientKyberKey);
// Returns encrypted blob.
```

#### `unwrapSessionKey(wrappedKey)`
Decrypt a session key using your private Kyber key.
```javascript
const sessionKey = await window.trustkeys.unwrapSessionKey(wrappedBlob);
// Triggers Approval Popup. Returns sessionKey (hex).
```

#### `unwrapManySessionKeys(wrappedKeys)`
Batch decrypt multiple session keys in a single approval step.
```javascript
const keys = await window.trustkeys.unwrapManySessionKeys([blob1, blob2, blob3]);
// Triggers ONE Approval Popup. Returns array of sessionKeys (null for failed ones).
```

---

## Key Management

- **Export / Back up Keys**: Settings > Export / Back up Keys. Requires the vault password and exports the **active account**. Two formats:
  - **Encrypted `.kvault`** (recommended): a passphrase-protected backup, importable on another device or by the Kryptolog web app (Receive → Backup file). Uses the shared `encryptVault` format (both apps call the same `@kryptolog/crypto-core` implementation, so the blob is byte-compatible with the SPA).
  - **Plain JSON**: unencrypted private keys — **store securely**.
  (Export is scoped to the active account: extension account ids are random UUIDs, so a multi-account export would lose the active selection on import.)
- **Import Keys**: Settings > Import Keys (JSON). Restores accounts from a plaintext JSON backup. Merges new accounts into the existing vault.
- **Manage Trusted Sites**: Settings > Manage Trusted Sites. View/add/remove authorized origins and toggle each site's "Allow silent message signing" capability. Dev defaults (localhost, 127.0.0.1) cannot be removed.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| UI | React 18, Manifest V3 |
| Build | Vite + @crxjs/vite-plugin |
| Crypto core | `@kryptolog/crypto-core` (shared with the web app, `file:` dep) |
| PQC Encryption | @noble/post-quantum — ML-KEM-768 (FIPS 203) |
| PQC Signatures | @noble/post-quantum — ML-DSA-44 (FIPS 204) |
| Vault | AES-256-GCM encrypted storage |
| Dynamic Scripts | chrome.scripting API |

---

## Disclaimer
This software implements NIST-standardized post-quantum algorithms (FIPS 203/204) via `@noble/post-quantum`, which has been formally audited. The broader application (vault storage, key management, authorization flows) has not undergone an independent security audit. Use for testing and development purposes only.
