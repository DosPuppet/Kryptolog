# TrustKeys - Post-Quantum Cryptography (PQC) Extension

TrustKeys is a quantum-resistant browser extension designed to secure interactions against future quantum computing threats. Every key it holds is **hybrid**: a post-quantum algorithm paired with a classical one, so each holds while either half does.

> **Status**: Beta (Production Functional)
> **Algorithms**: composite ML-DSA-65 + Ed25519 signatures, X-Wing (ML-KEM-768 + X25519) encryption — crypto-core 4.0.0
> **Role**: Primary PQC Authentication Provider for Kryptolog.

---

## Architecture & Security

### 1. Hybrid Post-Quantum Algorithms
NIST category 3 throughout, the level ANSSI asks for:
- **Encryption**: X-Wing (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem) via
  `@noble/post-quantum`
  - The shared secret stays secret while either ML-KEM-768 or X25519 holds.
  - It is run through **HKDF-SHA-384** (with a fixed context label) to derive the
    **AES-256-GCM** key that encrypts the message/session payload; the envelope's
    version and algorithm id are its associated data.
- **Signing**: composite ML-DSA-65 + Ed25519 (`id-MLDSA65-Ed25519-SHA512`,
  draft-ietf-lamps-pq-composite-sigs) via `@noble/post-quantum` and `@noble/curves`
  - A signature is valid only if both halves verify.
- **Address**: the SHA-384 of the identity key, 96 hex characters — the account's id.

These primitives are not implemented in the extension directly: they live in the
shared **`@kryptolog/crypto-core`** package (see below), which the extension and the
Kryptolog web app both consume so their wire/storage formats stay byte-identical.

### Shared crypto core (`@kryptolog/crypto-core`)
All client-side crypto (composite signatures, X-Wing, session-key wrapping, the
AES-GCM vault, domain separation) lives in **one** versioned package at
[`../packages/crypto-core`](../packages/crypto-core), consumed by both this extension
and the web app via a `file:` dependency. This replaced the two formerly duplicated
`crypto.js` copies and their hand-maintained "KEEP IN SYNC" comment.

`src/utils/crypto.js` is a thin shim that `export *`s from the package, and nothing
else since 4.0.0: an account's `id` is its address in both apps (the extension used
random UUIDs, so one identity was two accounts depending on who exported it). Because
there is a single source, byte-compatibility between the two builds is **structural**
and enforced by the package's suites (the drafts' vectors, golden bodies and
envelopes, a noble <-> OpenSSL fixture, and a `CRYPTO_CORE_VERSION` check) rather than
by a comment.

### 2. The Secure Vault
- **Zero-Knowledge Architecture**: Your private keys never leave the extension.
- **Encryption**: The vault is encrypted at rest using **AES-GCM (256-bit)**.
- **Key Derivation**: Your password derives the encryption key using **Argon2id** (46 MiB, one pass — the parameters travel in the vault, so they can be raised without a format change). The password must be at least 12 characters and not a sequence or a well-known password; the same rule applies to backup passphrases.
- **Format**: crypto-core 4.x — accounts stored as their seeds, every public value re-derived and checked on unlock. A vault or backup made before 4.0.0 is refused by name ("older Kryptolog version", on the unlock screen too); recreate it.
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
- **The extension builds what it signs.** A page cannot hand over a login challenge, a
  deletion or a multisig approval as a string: those have typed calls (below), and
  TrustKeys builds the signed body itself — with the origin Chrome reports for the page, so
  a site can only ever sign in to itself — and the approval window says in words what is
  being signed, with the exact bytes one click away.
- **Internal-only operations**: unlocking, locking, setting the password and the vault
  status can only be asked for by the extension's own pages, never by a site.
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
   npm run build:dev   # local development: http://localhost and 127.0.0.1 trusted by default
   npm run build       # production: no site is trusted until you add it (HTTPS only)
   ```
   The production build also prompts for every chat-message signature unless the site
   is granted silent message signing.
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

### Demo page
`trustkeys-demo/index.html` (at the repository root) is a dependency-free manual
test harness that exercises the generic methods on `window.trustkeys`. Serve it on
localhost with a `build:dev` extension and open it in the browser:

```bash
python3 -m http.server 5173 --directory ../trustkeys-demo
```

The connect, sign-in, signing and decryption flows are also covered automatically,
with the extension loaded unpacked into Chromium, by the end-to-end suite in
[`../e2e`](../e2e).

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
//   address: "hex...",              // the Kryptolog address: SHA-384 of the identity key
//   identityPublicKey: "hex...",    // composite ML-DSA-65 + Ed25519 key
//   encryptionPublicKey: "hex..."   // X-Wing key
// }
```

### Digital Signatures (composite ML-DSA-65 + Ed25519)

#### `sign(message)`
Sign a document with the active account's identity key. Accepts a
Kryptolog `content`-context body (a signed document, whose text the approval
window shows) or text that is not a Kryptolog body at all. **Refuses every other
Kryptolog context** — login, key attestation, multisig approval, account
deletion, chat message — which have their own typed calls below, so a site can
never get one of them signed by passing it as a string (crypto-core 3.0.0).
```javascript
const signature = await window.trustkeys.sign(contentDomainBody);
// Triggers Approval Popup. Returns a base64 signature.
```

#### `signLogin({ nonce, deployment })`
Sign a Kryptolog login challenge for **this page's own origin**. TrustKeys builds
the body itself, with the origin the browser attaches to the request and the
active account's encryption key, so a site can only ever sign in to itself.
```javascript
const { nonce, deployment } = await (await fetch(`${API}/auth/nonce/${address}`)).json();
const signature = await window.trustkeys.signLogin({ nonce, deployment });
// Approval window: "Sign in to Kryptolog at <origin>". Returns a base64 signature.
```

#### `getKeyAttestation()`
The active account's self-signed encryption-key attestation, naming its address. No
popup: the signed message is fixed and names nothing the page chose.

#### `signAccountDeletion({ nonce, mode, redactionKeys, deployment })`
Authorize deleting the account on this origin. `mode` is `"leave"` or `"erase"`;
the window states which, the account's address, and how many messages an erase
redacts.

#### `signConversationErase({ nonce, kind, conversation, redactionKeys, deployment })`
Authorize erasing your own messages in one conversation on this origin. `kind` is
`"dm"` (conversation = partner address) or `"group"` (conversation = channel id);
the window names the conversation and how many messages are redacted.

#### `signMultisigApproval({ workflowId, secretId, ciphertextSha384 })`
Approve a multisig workflow; the window names the workflow.

#### `signMessage(message)`
Sign a **chat message** with the active account's identity key. Unlike `sign()`,
this can sign **without** a per-message popup — but only for payloads in the
`message` domain (the call is refused otherwise), and only if the user enabled
"Allow silent message signing" for the site (default off; dev origins always
allowed in development builds only). For sites without that capability it
falls back to a per-message approval popup.
```javascript
const signature = await window.trustkeys.signMessage(messageDomainPayload);
// Returns a base64 signature. (Used by the messenger to authenticate messages.)
```

### Encryption (X-Wing + AES)

#### `encrypt(message, [publicKey])`
Encrypt data. If `publicKey` is omitted, encrypts for the active account (self).
```javascript
const encrypted = await window.trustkeys.encrypt("My Secret", recipientMlKemKey);
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
Encrypt a session key for a specific recipient using their ML-KEM public key.
```javascript
const wrapped = await window.trustkeys.wrapSessionKey(sessionKey, recipientMlKemKey);
// Returns encrypted blob.
```

#### `unwrapSessionKey(wrappedKey)`
Decrypt a session key using your private ML-KEM key.
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
- **Manage Trusted Sites**: Settings > Manage Trusted Sites. View/add/remove authorized origins and toggle each site's "Allow silent message signing" capability. In a development build (`npm run build:dev`) localhost and 127.0.0.1 are trusted by default; a production build injects into no page until you add it here.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| UI | React 18, Manifest V3 |
| Build | Vite + @crxjs/vite-plugin |
| Crypto core | `@kryptolog/crypto-core` (shared with the web app, `file:` dep) |
| PQC Encryption | @noble/post-quantum — X-Wing (ML-KEM-768 + X25519) |
| PQC Signatures | @noble/post-quantum + @noble/curves — composite ML-DSA-65 + Ed25519 |
| Vault | AES-256-GCM under Argon2id |
| Dynamic Scripts | chrome.scripting API |

---

## Disclaimer
This software implements NIST-standardized post-quantum algorithms (FIPS 203/204) via `@noble/post-quantum`. That library is self-audited and makes no side-channel claims; it has not had an independent third-party audit, and neither has this extension. Use for testing and development purposes only.
