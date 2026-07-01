// @kryptolog/crypto-core — the single source of truth for client-side crypto.
//
// NIST FIPS post-quantum primitives (audited, pure-TS, no WASM):
//   ML-KEM-768  (FIPS 203) — key encapsulation, replaces Kyber768
//   ML-DSA-44   (FIPS 204) — signatures,        replaces Dilithium2
// ML-DSA byte encoding is interop-verified against the server's liboqs.
//
// This package is consumed by BOTH the SPA (frontend/) and the TrustKeys
// extension (trustkeys/) via their respective Vite builds. There is exactly ONE
// copy of every wire/storage primitive here, so the "produced here, consumed
// there (and vice-versa)" byte-compatibility that used to be guarded by a
// hand-maintained "KEEP IN SYNC" comment is now structural. The guarantee is
// enforced by test/byte-compat.test.js (golden vectors + version guard), not by
// a comment. Each app's src/utils/crypto.js is a thin shim that re-exports this
// module and adds only its app-local glue (the `*PQC` aliases in the SPA, and
// each app's own generateAccount() id policy).
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';

// Bumped whenever a wire/storage format or shared primitive changes. The
// byte-compat test asserts both app builds resolve the SAME version, so a
// re-duplicated or version-skewed copy fails CI loudly.
// 1.1.0: messageSigningBody now binds the actual ciphertext (the AES-GCM
//        envelope object is serialized canonically instead of coercing to the
//        constant "[object Object]"), so message signatures change.
export const CRYPTO_CORE_VERSION = '1.1.0';

// Helper: Uint8Array/Array <-> Hex. Deliberately Buffer-free so this package
// stays a pure, runtime-agnostic ESM module (Node, browser SPA, MV3 extension)
// with no Node polyfill dependency — that's what lets a single symlinked copy
// build cleanly in both Vite apps. Output is byte-identical to the previous
// Buffer.from(...).toString('hex') (lowercase, two chars per byte).
const _HEX = [];
for (let i = 0; i < 256; i++) _HEX.push(i.toString(16).padStart(2, '0'));
export const toHex = (arr) => {
    const bytes = arr instanceof Uint8Array ? arr : new Uint8Array(arr);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += _HEX[bytes[i]];
    return hex;
};
export const fromHex = (hex) => {
    const len = hex.length >> 1;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
};

// Derive the AES-GCM key from an ML-KEM shared secret via HKDF-SHA-256 with a
// fixed context label (audit S5), instead of importing the raw shared secret as
// the AES key. The ML-KEM secret is already uniform, so this is best-practice
// hygiene + domain binding, not a fix for a weakness. This changes the wire
// format: ciphertext produced before this no longer decrypts (acceptable under
// the clean-cutover stance).
const KEM_KDF_INFO = 'Kryptolog/ML-KEM-768/AES-GCM/v1';
const kemAesKey = async (sharedSecret, usage) => {
    const ikm = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(KEM_KDF_INFO) },
        ikm,
        { name: 'AES-GCM', length: 256 },
        false,
        usage
    );
};

// --- Domain separation (audit H1) ---
// Every signed payload is wrapped with a context tag *before* it is signed, so a
// signature minted for one purpose (e.g. approving multisig/document content)
// can never be replayed as another (e.g. a login challenge). The context is
// fixed here by the calling code — never drawn from user-supplied content — and
// the header line cannot be reproduced by a content body, so the namespaces are
// disjoint. The server (backend/auth.py `_login_message`) and the Ethereum path
// apply the identical wrapper, so signatures stay interoperable across libs.
export const SIGNING_CONTEXT = Object.freeze({
    LOGIN: 'login',
    CONTENT: 'content',
    MULTISIG_APPROVAL: 'multisig-approval',
    MESSAGE: 'message',
});
const DS_HEADER = 'Kryptolog Signed Message v1';
export const domainSeparate = (context, body) => `${DS_HEADER}\ncontext=${context}\n${body}`;

// The exact prefix of any `message`-context payload. The extension's silent
// message-signing path checks for this so it will ONLY auto-sign chat messages,
// never a login / multisig / content signature (those use other contexts).
export const MESSAGE_SIGNING_PREFIX = domainSeparate(SIGNING_CONTEXT.MESSAGE, '');

// Canonicalize the ciphertext field for signing. Production passes the AES-GCM
// envelope OBJECT { iv, content } (as returned by encryptWithSessionKey); a bare
// string (an already-serialized ct) is signed as-is. This explicit serialization
// is load-bearing: interpolating the object directly would coerce it to the
// constant "[object Object]", so the signature would NOT commit to the real
// ciphertext and any same-session ciphertext could be swapped under a valid
// signature. iv/content are hex, so a '.' separator is unambiguous.
const canonicalCiphertext = (ct) =>
    (ct && typeof ct === 'object') ? `${ct.iv}.${ct.content}` : ct;

// Canonical bytes a sender signs for one chat message (audit S1: authenticate
// messages end-to-end, not just encrypt them). Binds the author, the
// conversation (DM recipient address or group channel id), the session id, and
// the exact ciphertext, under the `message` domain so it can't be replayed as
// another signature type. Sender and every receiver build this identically:
//   from = message.sender_address, conv = recipient_address (DM) | channel_id (group).
export const messageSigningBody = ({ from, conv, sid, ct }) =>
    domainSeparate(SIGNING_CONTEXT.MESSAGE, `from=${from}\nconv=${conv}\nsid=${sid}\nct=${canonicalCiphertext(ct)}`);

// SHA-256 of a UTF-8 string -> lowercase hex (matches Python hashlib.sha256().hexdigest()).
export const sha256Hex = async (str) => {
    const bytes = new TextEncoder().encode(str);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return toHex(new Uint8Array(digest));
};

// Server-verifiable multisig approval message (audit M1). A signer approves a
// workflow by signing the SHA-256 of the STORED CIPHERTEXT, bound to the
// workflow + secret id. The server is zero-knowledge (can't see plaintext) but
// can hash the ciphertext it holds, so it can verify this. Must be byte-
// identical to the server's auth.multisig_approval_message().
export const multisigApprovalMessage = (workflowId, secretId, ciphertextSha256Hex) =>
    domainSeparate(
        SIGNING_CONTEXT.MULTISIG_APPROVAL,
        `workflow=${workflowId}\nsecret=${secretId}\nct=${ciphertextSha256Hex}`
    );

// --- Device transfer passphrase ---
// A high-entropy (128-bit) human-transcribable passphrase for one-time
// device-to-device vault transfer. Crockford base32 (no 0/1/O/I ambiguity),
// grouped for readability: e.g. "K7Q4-9F2M-RX83-...". Carried out of band
// (QR / typed) — never sent to the server.
const _B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const generateTransferCode = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16)); // 128 bits
    let bits = '';
    for (const b of bytes) bits += b.toString(2).padStart(8, '0');
    let out = '';
    for (let i = 0; i < bits.length; i += 5) {
        out += _B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
    }
    // Group into 4-char blocks for legibility.
    return out.match(/.{1,4}/g).join('-');
};

// --- PQC Implementations ---

// ML-KEM-768 keypair (encryption / key encapsulation).
// Name kept as "Kyber" for storage-schema and call-site stability.
export const generateKyberKeyPair = async () => {
    try {
        const { publicKey, secretKey } = ml_kem768.keygen();
        return {
            publicKey: toHex(publicKey),
            privateKey: toHex(secretKey),
        };
    } catch (e) {
        console.error("ML-KEM keygen failed", e);
        throw e;
    }
};

// ML-DSA-44 keypair (signing). Name kept as "Dilithium" for stability.
export const generateDilithiumKeyPair = async () => {
    try {
        const { publicKey, secretKey } = ml_dsa44.keygen();
        return {
            publicKey: toHex(publicKey),
            privateKey: toHex(secretKey),
        };
    } catch (e) {
        console.error("ML-DSA keygen failed", e);
        throw e;
    }
};

// ML-DSA-44 detached signature over the UTF-8 message bytes.
export const signMessage = async (message, privateKeyHex) => {
    const secretKey = fromHex(privateKeyHex);
    const msgBytes = new TextEncoder().encode(message);
    // noble API: sign(message, secretKey) -> detached signature
    const signature = ml_dsa44.sign(msgBytes, secretKey);
    return toHex(signature);
};

// Exact-match verification (audit H4): a signature is valid iff ML-DSA verifies
// the detached signature against exactly the given message + public key.
export const verifySignature = async (message, signatureHex, publicKeyHex) => {
    try {
        const signature = fromHex(signatureHex);
        const publicKey = fromHex(publicKeyHex);
        const msgBytes = new TextEncoder().encode(message);
        // noble API: verify(signature, message, publicKey) -> boolean
        return ml_dsa44.verify(signature, msgBytes, publicKey);
    } catch (e) {
        console.error("verifySignature failed", e);
        return false;
    }
};

export const encryptMessage = async (message, publicKeyHex) => {
    // Hybrid Encryption (KEM + AES-GCM):
    // 1. Kyber KEM Encapsulate -> Shared Secret (ss) + Ciphertext (ct)
    // 2. Use ss as AES key
    // 3. Encrypt message with ss (AES-GCM) -> content, iv

    const publicKey = fromHex(publicKeyHex);

    // ML-KEM-768 encapsulate -> { cipherText (1088B), sharedSecret (32B) }
    const { cipherText: ct, sharedSecret: ss } = ml_kem768.encapsulate(publicKey);

    // Derive the AES key from the shared secret via HKDF (audit S5).
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await kemAesKey(new Uint8Array(ss), ["encrypt"]);

    const enc = new TextEncoder();
    const encodedMsg = enc.encode(message);

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedMsg
    );

    return {
        kem: toHex(ct), // Just send the KEM ciphertext (hex)
        iv: toHex(iv),
        content: toHex(new Uint8Array(encryptedContent))
    };
};

export const decryptMessage = async (encryptedData, privateKeyHex) => {
    // encryptedData: { kem: hexString, iv, content }
    const privateKey = fromHex(privateKeyHex);

    // Parse KEM ciphertext
    const ct = fromHex(encryptedData.kem);

    // ML-KEM-768 decapsulate -> shared secret (ss, 32B)
    const ss = ml_kem768.decapsulate(ct, privateKey);

    const iv = fromHex(encryptedData.iv);
    const content = fromHex(encryptedData.content);

    const key = await kemAesKey(new Uint8Array(ss), ["decrypt"]);

    const decryptedContent = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        content
    );

    const dec = new TextDecoder();
    return dec.decode(decryptedContent);
};

// --- Session Key Implementations (Local) ---

export const generateSessionKey = async () => {
    // Generate 256-bit AES key (32 bytes)
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    return toHex(keyBytes);
};

export const wrapSessionKey = async (sessionKeyHex, publicKeyHex) => {
    // 1. Encapsulate a shared secret for the receiver (ML-KEM-768)
    const publicKey = fromHex(publicKeyHex);
    const { cipherText: ct, sharedSecret: ss } = ml_kem768.encapsulate(publicKey);

    // 2. Use Shared Secret (HKDF-derived, audit S5) to encrypt the Session Key
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const kek = await kemAesKey(new Uint8Array(ss), ["encrypt"]);

    const sessKeyBytes = fromHex(sessionKeyHex);
    const encryptedKey = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        kek,
        sessKeyBytes
    );

    return {
        kem: toHex(ct),
        iv: toHex(iv),
        encKey: toHex(new Uint8Array(encryptedKey)) // Standardized name
    };
};

export const unwrapSessionKey = async (wrappedKey, privateKeyHex) => {
    // wrappedKey: { kem, iv, ct }
    const privateKey = fromHex(privateKeyHex);
    const ct = fromHex(wrappedKey.kem);

    // 1. Decapsulate Shared Secret (ML-KEM-768)
    const ss = ml_kem768.decapsulate(ct, privateKey);

    // 2. Decrypt Session Key
    const iv = fromHex(wrappedKey.iv);
    // Support 'encKey' (new standard) or 'ct' (legacy/frontend-local)
    const encryptedKey = fromHex(wrappedKey.encKey || wrappedKey.ct);

    const kek = await kemAesKey(new Uint8Array(ss), ["decrypt"]); // HKDF (audit S5)

    const decryptedKeyBytes = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        kek,
        encryptedKey
    );

    return toHex(new Uint8Array(decryptedKeyBytes));
};

export const encryptWithSessionKey = async (message, sessionKeyHex) => {
    const keyBytes = fromHex(sessionKeyHex);
    // Use AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
        "raw", keyBytes, "AES-GCM", false, ["encrypt"]
    );

    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(message)
    );

    return {
        iv: toHex(iv),
        content: toHex(new Uint8Array(encrypted))
    };
};

export const decryptWithSessionKey = async (encryptedData, sessionKeyHex) => {
    // encryptedData: { iv, content }
    const keyBytes = fromHex(sessionKeyHex);
    const iv = fromHex(encryptedData.iv);
    const content = fromHex(encryptedData.content);

    const key = await crypto.subtle.importKey(
        "raw", keyBytes, "AES-GCM", false, ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        content
    );

    const dec = new TextDecoder();
    return dec.decode(decrypted);
};

// --- Symmetric Encryption (AES-GCM 256) for Envelope / Large Files ---

export const generateSymmetricKey = async () => {
    // Generate 256-bit AES key (32 bytes)
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    return toHex(keyBytes);
};

export const encryptSymmetric = async (content, keyHex) => {
    const keyBytes = fromHex(keyHex);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
        "raw", keyBytes, "AES-GCM", false, ["encrypt"]
    );

    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(content)
    );

    return {
        iv: toHex(iv),
        ciphertext: toHex(new Uint8Array(encrypted))
    };
};

export const decryptSymmetric = async (encryptedObject, keyHex) => {
    // encryptedObject: { iv, ciphertext }
    const keyBytes = fromHex(keyHex);
    const iv = fromHex(encryptedObject.iv);
    const ciphertext = fromHex(encryptedObject.ciphertext);

    const key = await crypto.subtle.importKey(
        "raw", keyBytes, "AES-GCM", false, ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
    );

    const dec = new TextDecoder();
    return dec.decode(decrypted);
};

// --- Binary Chunk Encryption (for chunked file uploads) ---

const importAesKey = async (keyHex) => {
    const keyBytes = fromHex(keyHex);
    return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
};

/**
 * Encrypt a binary chunk (Uint8Array) with AES-GCM.
 * Returns { iv: hex, ciphertext: hex }
 */
export const encryptChunk = async (chunkBytes, keyHex) => {
    const key = await importAesKey(keyHex);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, chunkBytes);
    return { iv: toHex(iv), ciphertext: toHex(new Uint8Array(encrypted)) };
};

/**
 * Decrypt a binary chunk. Returns Uint8Array (raw bytes).
 */
export const decryptChunk = async (ivHex, ciphertextHex, keyHex) => {
    const key = await importAesKey(keyHex);
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromHex(ivHex) }, key, fromHex(ciphertextHex)
    );
    return new Uint8Array(decrypted);
};

// --- Vault Security ---

// Helper to derive key
export async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 600000, // OWASP Recommended (was 100k)
            hash: "SHA-512"   // Hardened from SHA-256
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypts a data object (vault) with a password.
 */
export const encryptVault = async (data, password) => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);

    const enc = new TextEncoder();
    const encodedData = enc.encode(JSON.stringify(data));

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
    );

    return {
        salt: toHex(salt),
        iv: toHex(iv),
        data: toHex(new Uint8Array(encryptedContent)) // Returns Hex for easy storage
    };
};

/**
 * Decrypts a vault using a password.
 */
export const decryptVault = async (encryptedVault, password) => {
    const salt = fromHex(encryptedVault.salt);
    const iv = fromHex(encryptedVault.iv);
    const data = fromHex(encryptedVault.data);

    const key = await deriveKey(password, salt);

    try {
        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        const dec = new TextDecoder();
        return JSON.parse(dec.decode(decryptedContent));
    } catch (e) {
        throw new Error("Incorrect password or corrupted data");
    }
};

/**
 * Encrypts a data object (vault) with a pre-derived CryptoKey and salt.
 * IV is still random per call — safe to reuse the same key+salt.
 */
export const encryptVaultWithKey = async (data, key, salt) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const encodedData = enc.encode(JSON.stringify(data));

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
    );

    return {
        salt: toHex(salt),
        iv: toHex(iv),
        data: toHex(new Uint8Array(encryptedContent))
    };
};

/**
 * Decrypts a vault using a pre-derived CryptoKey.
 */
export const decryptVaultWithKey = async (encryptedVault, key) => {
    const iv = fromHex(encryptedVault.iv);
    const data = fromHex(encryptedVault.data);

    try {
        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        const dec = new TextDecoder();
        return JSON.parse(dec.decode(decryptedContent));
    } catch (e) {
        throw new Error("Decryption failed with cached key");
    }
};

// --- WebAuthn PRF (Biometric Vault) ---

export const checkPrfSupport = async () => {
    try {
        if (!window.PublicKeyCredential) return false;
        // We can't reliably detect PRF support before attempting credential creation.
        // The actual check happens during registration by inspecting extension results.
        return true;
    } catch (e) {
        return false;
    }
};

/**
 * Creates a new WebAuthn credential for biometric vault unlock.
 *
 * Requires a HARDWARE-BOUND key via the WebAuthn PRF extension (iOS, modern
 * desktop Chrome/Firefox). There is intentionally no software fallback: a
 * non-hardware-bound key would have to live in JS-readable storage, which
 * defeats the vault's at-rest encryption. On devices without PRF this throws
 * and biometric unlock is simply not offered.
 *
 * Returns: { mode: 'prf', credentialId, prfKey (hex), prfSalt (hex) }
 */
export const registerBiometricCredential = async (username) => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const prfSalt = crypto.getRandomValues(new Uint8Array(32));

    const creationOptions = {
        publicKey: {
            challenge,
            rp: {
                name: "Kryptolog Vault",
                id: window.location.hostname
            },
            user: {
                id: userId,
                name: username,
                displayName: username
            },
            pubKeyCredParams: [
                { type: "public-key", alg: -7 },   // ES256
                { type: "public-key", alg: -257 }  // RS256
            ],
            authenticatorSelection: {
                // 'platform' forces the device's own biometrics (fingerprint/face)
                // instead of the cross-device picker (Bluetooth/QR/another phone)
                authenticatorAttachment: "platform",
                residentKey: "preferred",
                userVerification: "required"
            },
            extensions: {
                prf: {
                    eval: { first: prfSalt }
                }
            }
        }
    };

    const credential = await navigator.credentials.create(creationOptions);
    const extResults = credential.getClientExtensionResults();

    // Hardware-bound PRF path (iOS, desktop Chrome, Firefox).
    if (extResults.prf && extResults.prf.results && extResults.prf.results.first) {
        const prfBytes = new Uint8Array(extResults.prf.results.first);
        return {
            mode: 'prf',
            credentialId: credential.id,
            prfKey: toHex(prfBytes),
            prfSalt: toHex(prfSalt)
        };
    }

    // No PRF => no hardware-bound key. We deliberately do NOT fall back to a
    // localStorage-stored key (that would expose a vault-unlocking secret to any
    // XSS / local read). Biometric unlock is unavailable; the user uses their password.
    throw new Error(
        "This device doesn't support hardware-bound biometric keys (WebAuthn PRF), " +
        "so biometric unlock isn't available here. You can still unlock with your password."
    );
};

/**
 * Authenticates with an existing credential and derives the hardware-bound key
 * from the WebAuthn PRF extension result. Returns the key as hex.
 *
 * `mode` exists only to reject legacy 'fallback' credentials (the insecure
 * localStorage path has been removed) — those users must re-enable biometrics.
 */
export const getBiometricKey = async (credentialId, prfSaltHex, mode = 'prf') => {
    if (mode !== 'prf') {
        throw new Error(
            "This biometric credential uses an unsupported legacy mode. Please disable " +
            "and re-enable biometric unlock to use a hardware-bound key."
        );
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const extensions = {
        prf: {
            eval: {
                first: prfSaltHex ? fromHex(prfSaltHex) : new Uint8Array(32).fill(1)
            }
        }
    };

    const requestOptions = {
        publicKey: {
            challenge,
            rpId: window.location.hostname,
            allowCredentials: [{
                id: fromBase64Url(credentialId),
                type: "public-key",
                // 'internal' hints to Chrome that this is a platform credential
                // preventing the cross-device (Bluetooth/QR) picker from appearing
                transports: ["internal"]
            }],
            userVerification: "required",
            extensions
        }
    };

    // This triggers the biometric prompt on the device
    const assertion = await navigator.credentials.get(requestOptions);

    const extResults = assertion.getClientExtensionResults();
    if (!extResults.prf || !extResults.prf.results || !extResults.prf.results.first) {
        throw new Error("Biometric auth succeeded but PRF key was not returned. Your device may not support hardware-bound biometrics.");
    }
    return toHex(new Uint8Array(extResults.prf.results.first));
};

// Helper for Base64URL -> Uint8Array
const fromBase64Url = (str) => {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd((base64.length + 3) & ~3, '=');
    const bin = atob(padded);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        arr[i] = bin.charCodeAt(i);
    }
    return arr;
};
