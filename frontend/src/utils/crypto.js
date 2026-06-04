// NIST FIPS post-quantum primitives (audited, pure-TS, no WASM):
//   ML-KEM-768  (FIPS 203) — key encapsulation, replaces Kyber768
//   ML-DSA-44   (FIPS 204) — signatures,        replaces Dilithium2
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { Buffer } from 'buffer';
import { encrypt } from '@metamask/eth-sig-util';
import { verifyMessage, BrowserProvider } from 'ethers';

// Helper: Uint8Array/Array <-> Hex
export const toHex = (arr) => Buffer.from(arr).toString('hex');
export const fromHex = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));

// --- Web3 / MetaMask Helpers (Restored) ---

export const connectWallet = async () => {
    if (!window.ethereum) {
        throw new Error("MetaMask not found. Please install it.");
    }
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    return accounts[0];
};

export const getEncryptionPublicKey = async (address) => {
    if (!window.ethereum) {
        throw new Error("MetaMask not found.");
    }
    try {
        const key = await window.ethereum.request({
            method: 'eth_getEncryptionPublicKey',
            params: [address],
        });
        return key;
    } catch (error) {
        if (error.code === 4001) {
            throw new Error("User rejected public key request");
        }
        throw error;
    }
};

export const encryptData = (data, publicKey) => {
    const encrypted = encrypt({
        publicKey: publicKey,
        data: data,
        version: 'x25519-xsalsa20-poly1305',
    });
    return JSON.stringify(encrypted);
};

export const decryptData = async (encryptedDataStr, address) => {
    if (!window.ethereum) {
        throw new Error("MetaMask not found.");
    }
    try {
        const hexEncoded = '0x' + Buffer.from(encryptedDataStr).toString('hex');

        const decrypted = await window.ethereum.request({
            method: 'eth_decrypt',
            params: [hexEncoded, address],
        });
        return decrypted;
    } catch (error) {
        console.error("Decryption failed:", error);
        throw error;
    }
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

export const generateAccount = async (name) => {
    const kyber = await generateKyberKeyPair();
    const dilithium = await generateDilithiumKeyPair();

    return {
        id: dilithium.publicKey, // Use Public Key as ID for consistency
        name,
        kyber,
        dilithium,
        createdAt: Date.now(),
    };
};

// ML-DSA-44 detached signature over the UTF-8 message bytes.
export const signMessagePQC = async (message, privateKeyHex) => {
    const secretKey = fromHex(privateKeyHex);
    const msgBytes = new TextEncoder().encode(message);
    // noble API: sign(message, secretKey) -> detached signature
    const signature = ml_dsa44.sign(msgBytes, secretKey);
    return toHex(signature);
};

// Exact-match verification (audit H4): a signature is valid iff ML-DSA verifies
// the detached signature against exactly the given message + public key.
export const verifySignaturePQC = async (message, signatureHex, publicKeyHex) => {
    try {
        const signature = fromHex(signatureHex);
        const publicKey = fromHex(publicKeyHex);
        const msgBytes = new TextEncoder().encode(message);
        // noble API: verify(signature, message, publicKey) -> boolean
        return ml_dsa44.verify(signature, msgBytes, publicKey);
    } catch (e) {
        console.error("verifySignaturePQC failed", e);
        return false;
    }
};

export const encryptMessagePQC = async (message, publicKeyHex) => {
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

export const decryptMessagePQC = async (encryptedData, privateKeyHex) => {
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

    // 2. Use Shared Secret to encrypt the Session Key
    const kekSeed = new Uint8Array(ss);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const kek = await crypto.subtle.importKey(
        "raw", kekSeed, "AES-GCM", false, ["encrypt"]
    );

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
    const kekSeed = new Uint8Array(ss);

    // 2. Decrypt Session Key
    const iv = fromHex(wrappedKey.iv);
    // Support 'encKey' (new standard) or 'ct' (legacy/frontend-local)
    const encryptedKey = fromHex(wrappedKey.encKey || wrappedKey.ct);

    const kek = await crypto.subtle.importKey(
        "raw", kekSeed, "AES-GCM", false, ["decrypt"]
    );

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

// --- Web3 Signature (Legacy Name) ---
export const signMessage = async (message, address) => {
    const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [message, address],
    });
    return signature;
}

// Safe Ethers-based signing (matches verifyMessage)
export const signMessageEth = async (message) => {
    try {
        const provider = new BrowserProvider(window.ethereum);
        const signer = await provider.getSigner();
        // Ethers handles hex/string conversion automatically matching verifyMessage
        return await signer.signMessage(message);
    } catch (e) {
        console.error("signMessageEth failed", e);
        throw e;
    }
};

export const verifyMessageEth = (message, signature) => {
    try {
        return verifyMessage(message, signature);
    } catch (e) {
        console.error("Eth signature verification failed", e);
        return null;
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
 * Creates a new WebAuthn credential.
 * Tries PRF extension first (iOS, modern desktop Chrome).
 * Falls back to a localStorage-stored random key gated by WebAuthn assertion (Android).
 *
 * Returns:
 *   PRF mode:      { mode: 'prf',      credentialId, prfKey (hex), prfSalt (hex) }
 *   Fallback mode: { mode: 'fallback', credentialId }
 *   (In fallback mode, the random key is stored in localStorage under 'kryptolog_bio_fallback_key')
 */
export const registerBiometricCredential = async (username) => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const prfSalt = crypto.getRandomValues(new Uint8Array(32));

    const creationOptions = {
        publicKey: {
            challenge,
            rp: {
                name: "SecureLog Vault",
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

    // --- PRF path (iOS, desktop Chrome, Firefox) ---
    if (extResults.prf && extResults.prf.results && extResults.prf.results.first) {
        const prfBytes = new Uint8Array(extResults.prf.results.first);
        return {
            mode: 'prf',
            credentialId: credential.id,
            prfKey: toHex(prfBytes),
            prfSalt: toHex(prfSalt)
        };
    }

    // --- Fallback path (Android Chrome without PRF support) ---
    // Generate a random key and store it in localStorage.
    // The WebAuthn assertion (biometric check) acts as the UI gate.
    // SECURITY NOTE: This key is stored in localStorage and is not hardware-bound.
    const fallbackKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const fallbackKey = toHex(fallbackKeyBytes);
    localStorage.setItem('kryptolog_bio_fallback_key', fallbackKey);

    return {
        mode: 'fallback',
        credentialId: credential.id
    };
};

/**
 * Authenticates with an existing credential.
 * mode: 'prf'      → derives key from PRF extension result (hardware-bound)
 * mode: 'fallback' → reads key from localStorage after assertion succeeds (biometric gate only)
 *
 * Returns the key as hex.
 */
export const getBiometricKey = async (credentialId, prfSaltHex, mode = 'prf') => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const extensions = mode === 'prf' ? {
        prf: {
            eval: {
                first: prfSaltHex ? fromHex(prfSaltHex) : new Uint8Array(32).fill(1)
            }
        }
    } : {};

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

    if (mode === 'prf') {
        const extResults = assertion.getClientExtensionResults();
        if (!extResults.prf || !extResults.prf.results || !extResults.prf.results.first) {
            throw new Error("Biometric auth succeeded but PRF key was not returned. Your device may not support hardware-bound biometrics.");
        }
        const prfBytes = new Uint8Array(extResults.prf.results.first);
        return toHex(prfBytes);
    }

    // Fallback mode: assertion succeeded (biometric verified), now read key from localStorage
    const fallbackKey = localStorage.getItem('kryptolog_bio_fallback_key');
    if (!fallbackKey) {
        throw new Error("Biometric fallback key not found. Please re-enable biometrics.");
    }
    return fallbackKey;
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
