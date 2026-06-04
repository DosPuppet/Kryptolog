# TrustKeys - Post-Quantum Cryptography (PQC) Extension

TrustKeys is a quantum-resistant browser extension designed to secure interactions against future quantum computing threats. It implements the **Module-Lattice-based Key Encapsulation Mechanism (ML-KEM)** and **Digital Signature Algorithm (ML-DSA)** standards.

> **Status**: Beta (Production Functional)
> **Algorithms**: Crystals-Kyber-768 (ML-KEM) & Crystals-Dilithium-2 (ML-DSA)
> **Role**: Primary PQC Authentication Provider for Kryptolog.

---

## Architecture & Security

### 1. Quantum-Proof Algorithms
TrustKeys utilizes the NIST multi-round selected algorithms for post-quantum security:
- **Encryption**: [Crystals-Kyber-768](https://pq-crystals.org/kyber/) (ML-KEM)
  - Used for securely establishing shared secrets (Key Encapsulation).
  - Hybrid Encryption: Kyber derives a shared secret, which is then used to encrypt messages via **AES-256-GCM**.
- **Signing**: [Crystals-Dilithium-2](https://pq-crystals.org/dilithium/) (ML-DSA)
  - Used for generating unforgeable digital signatures.

### 2. The Secure Vault
- **Zero-Knowledge Architecture**: Your private keys never leave the extension.
- **Encryption**: The vault is encrypted at rest using **AES-GCM (256-bit)**.
- **Key Derivation**: Your password derives the encryption key using **PBKDF2** (SHA-256, 100,000 iterations).
- **Memory-Only Decryption**: Private keys are decrypted into memory *only* when the vault is unlocked.
- **Session Persistence**: The vault remains unlocked for **1 Hour** of inactivity. The encryption key is stored in `chrome.storage.session` (in-memory), which is **automatically wiped** when the browser is closed.

### 3. MPC Recovery (Google Backup) -- WIP
TrustKeys supports **Multi-Party Computation (MPC)** based recovery.
- **How it works**: Your Vault Key is split into shares.
- **Google Share**: One share is encrypted and stored associated with your Google ID.
- **Data Privacy**: Google *never* sees your private keys. They only authenticate your identity to retrieve an encrypted shard.
- **Restoration**: You can restore your PQC identity on a new device by authenticating with Google.

### 4. Authorization Model
TrustKeys enforces a strict "User Consent" model similar to Ethereum wallets:
- **Dynamic Site Authorization**: No site has access by default. Users authorize sites explicitly via the extension popup or Settings.
- **Connection**: Websites cannot access your account or public keys until you explicitly approve a `connect()` request.
- **Transaction Approval**: Every usage of a private key (Signing or Decrypting) triggers a popup requiring your manual confirmation.
- **Trusted Sites Management**: Authorized origins are stored in the encrypted vault and can be added or removed from Settings.
- **Dev Defaults**: Only `localhost` and `127.0.0.1` are pre-authorized (for development). All other sites — including production domains — require explicit user authorization on first use.
- **Dynamic Content Script Injection**: When a site is authorized, TrustKeys registers content scripts dynamically via `chrome.scripting.registerContentScripts()`. The page reloads and `window.trustkeys` becomes available at `document_start`.

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
You can configure the backend API and Frontend Bridge URL in the Settings menu:
1. Open Extension > Settings.
2. Click **Config (API & Bridge)**.
3. **API URL**: The backend server URL (Default: `http://localhost:8000`).
4. **Bridge URL**: The frontend URL hosting the Google OAuth Bridge (Default: `http://localhost:5173`).

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
Sign a message using the active account's Dilithium private key.
```javascript
const signature = await window.trustkeys.sign("Login Nonce: 12345");
// Triggers Approval Popup. Returns hex-encoded signature.
```

#### `verify(message, signature, publicKey)`
Verify a Dilithium signature against a public key.
```javascript
const valid = await window.trustkeys.verify(message, signature, publicKey);
// Returns boolean.
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

- **Export Keys**: Settings > Export Keys (JSON). Requires vault password. Generates a JSON backup of all accounts (private + public keys). **The backup file is unencrypted — store securely!**
- **Import Keys**: Settings > Import Keys. Restores accounts from a JSON backup. Merges new accounts into the existing vault.
- **Manage Trusted Sites**: Settings > Manage Trusted Sites. View, add, or remove authorized origins. Dev defaults (localhost, 127.0.0.1) cannot be removed.
- **MPC Backup**: Settings > Backup/Restore via Google ID.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| UI | React 18, Manifest V3 |
| Build | Vite + @crxjs/vite-plugin |
| PQC Encryption | crystals-kyber (ML-KEM 768) |
| PQC Signatures | dilithium-crystals-js (ML-DSA 2) |
| Vault | AES-256-GCM encrypted storage |
| Dynamic Scripts | chrome.scripting API |

---

## Disclaimer
This software uses experimental cryptographic standards. While Kyber and Dilithium are NIST-selected, this specific implementation has not undergone a formal security audit. Use for testing and development purposes only.
