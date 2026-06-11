// NIST FIPS post-quantum primitives (audited, pure-TS, no WASM):
//   ML-KEM-768  (FIPS 203) — key encapsulation, replaces Kyber768
//   ML-DSA-44   (FIPS 204) — signatures,        replaces Dilithium2
// ML-DSA byte encoding is interop-verified against the server's liboqs.
//
// ┌─ SHARED CRYPTO CORE — KEEP IN SYNC ───────────────────────────────────────┐
// │ Sibling: frontend/src/utils/crypto.js. The two files are independent       │
// │ copies (separate Vite builds) of the same primitives. The wire/storage     │
// │ formats below are produced here and consumed by the SPA (and vice-versa),  │
// │ so they MUST stay byte-compatible. Verified identical as of 2026-06-11:    │
// │   • KEM message envelope ...... { kem, iv, content }  (all hex)            │
// │   • session-key wrap .......... { kem, iv, encKey }   (all hex)            │
// │   • vault blob ................ { salt, iv, data }    (all hex)            │
// │   • KDF ....................... PBKDF2, 600000 iters, SHA-512 → AES-GCM-256 │
// │   • AEAD ...................... AES-GCM, fresh 12-byte random IV per call   │
// │ Naming: this file is PQC-only, so functions are bare (signMessage,         │
// │ verifySignature, encryptMessage, decryptMessage). The SPA suffixes the     │
// │ same functions with `PQC` (signMessagePQC, …) because it ALSO has `*Eth`   │
// │ variants (in web3.js). Behavior is identical; only the names differ.       │
// │ The SPA additionally has helpers absent here ON PURPOSE — domain           │
// │ separation (domainSeparate / multisigApprovalMessage / sha256Hex), chunked │
// │ file enc, encryptVaultWithKey, and WebAuthn-PRF biometrics. The extension  │
// │ signs the exact bytes the page hands it, so H1 domain-wrapping is applied  │
// │ at the SPA's call sites, not here. Change a shared format? Edit BOTH files.│
// └────────────────────────────────────────────────────────────────────────────┘
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { Buffer } from 'buffer';

// Helper: Uint8Array/Array <-> Hex
const toHex = (arr) => Buffer.from(arr).toString('hex');
const fromHex = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));

// ML-KEM-768 keypair (encryption). Name kept as "Kyber" for storage stability.
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

// ML-DSA-44 keypair (signing). Name kept as "Dilithium" for storage stability.
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

export const generateAccount = async (name) => {
    const kyber = await generateKyberKeyPair();
    const dilithium = await generateDilithiumKeyPair();

    return {
        id: crypto.randomUUID(),
        name,
        kyber,
        dilithium,
        createdAt: Date.now(),
    };
};

export const signMessage = async (message, privateKeyHex) => {
    const secretKey = fromHex(privateKeyHex);
    const msgBytes = new TextEncoder().encode(message);
    // noble API: sign(message, secretKey) -> detached ML-DSA-44 signature
    return toHex(ml_dsa44.sign(msgBytes, secretKey));
};

export const verifySignature = async (message, signatureHex, publicKeyHex) => {
    try {
        const signature = fromHex(signatureHex);
        const publicKey = fromHex(publicKeyHex);
        const msgBytes = new TextEncoder().encode(message);
        // noble API: verify(signature, message, publicKey) -> boolean (exact match)
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

    // Use ss as AES key
    const seed = new Uint8Array(ss); // Shared secret is 32 bytes

    // AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
        "raw",
        seed,
        "AES-GCM",
        false,
        ["encrypt"]
    );

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
    const seed = new Uint8Array(ss);

    const iv = fromHex(encryptedData.iv);
    const content = fromHex(encryptedData.content);

    const key = await crypto.subtle.importKey(
        "raw",
        seed,
        "AES-GCM",
        false,
        ["decrypt"]
    );

    const decryptedContent = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        content
    );

    const dec = new TextDecoder();
    return dec.decode(decryptedContent);
};

// --- Session Key Architecture (Signal-Lite) ---

export const generateSessionKey = () => {
    // Generate a random 32-byte key for AES-256
    const key = crypto.getRandomValues(new Uint8Array(32));
    return toHex(key);
};

// Wrap a session key for a recipient: ML-KEM encapsulate, then AES-GCM the
// session key under the shared secret. Returns { kem, iv, encKey }.
export const wrapSessionKey = async (sessionKeyHex, recipientPubKeyHex) => {
    const pk = fromHex(recipientPubKeyHex);
    const { cipherText: ct, sharedSecret: ss } = ml_kem768.encapsulate(pk);

    // Encrypt SessionKey with SS
    const startKey = await crypto.subtle.importKey(
        "raw", ss, "AES-GCM", false, ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sessionKeyBytes = fromHex(sessionKeyHex);

    const encryptedKey = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        startKey,
        sessionKeyBytes
    );

    return {
        kem: toHex(ct),
        iv: toHex(iv),
        encKey: toHex(new Uint8Array(encryptedKey))
    };
};

export const unwrapSessionKey = async (wrappedKey, privateKeyHex) => {
    // wrappedKey: { kem, iv, encKey }
    const sk = fromHex(privateKeyHex);
    const ct = fromHex(wrappedKey.kem);

    // Decapsulate to get SS (ML-KEM-768)
    const ss = ml_kem768.decapsulate(ct, sk);

    // Decrypt SessionKey
    const unwrappingKey = await crypto.subtle.importKey(
        "raw", ss, "AES-GCM", false, ["decrypt"]
    );

    const decryptedBytes = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromHex(wrappedKey.iv) },
        unwrappingKey,
        fromHex(wrappedKey.encKey || wrappedKey.ct)
    );

    return toHex(new Uint8Array(decryptedBytes));
};

export const encryptWithSessionKey = async (message, sessionKeyHex) => {
    const keyBytes = fromHex(sessionKeyHex);
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


// --- Vault Security ---



// Helper to derive key
async function deriveKey(password, salt) {
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
            iterations: 600000,
            hash: "SHA-512"
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
        data: toHex(new Uint8Array(encryptedContent))
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
