import KyberPkg from 'crystals-kyber';
import { createDilithium } from 'dilithium-crystals-js';
import { Buffer } from 'buffer';
import { encrypt } from '@metamask/eth-sig-util';
import { verifyMessage, BrowserProvider } from 'ethers';

const { KeyGen768, Encrypt768, Decrypt768 } = KyberPkg;

// Polyfill for dilithium-crystals-js WASM loading
if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) window.chrome.runtime = {};
if (!window.chrome.runtime.getURL) {
    window.chrome.runtime.getURL = (path) => {
        // Remove leading ./ and return path relative to root
        return '/' + path.replace(/^\.\//, '');
    };
}

// Ensure initialization
let dilithium = null;
const initDilithium = async () => {
    if (!dilithium) {
        dilithium = await createDilithium();
    }
    return dilithium;
};

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

export const generateKyberKeyPair = async () => {
    try {
        const [pk, sk] = KeyGen768();
        return {
            publicKey: toHex(pk), // Array of numbers
            privateKey: toHex(sk), // Array of numbers
        };
    } catch (e) {
        console.error("Kyber keygen failed", e);
        throw e;
    }
};

export const generateDilithiumKeyPair = async () => {
    try {
        const mod = await initDilithium();

        // Generate valid random seed to ensure uniqueness
        const seed = new Uint8Array(32);
        crypto.getRandomValues(seed);

        // Pass seed to generateKeys (level, seed)
        const { publicKey, privateKey } = mod.generateKeys(2, seed);

        return {
            publicKey: toHex(publicKey),
            privateKey: toHex(privateKey),
        };
    } catch (e) {
        console.error("Dilithium keygen failed", e);
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

export const signMessagePQC = async (message, privateKeyHex) => {
    const mod = await initDilithium();
    const privateKey = fromHex(privateKeyHex);
    const msgBytes = new TextEncoder().encode(message);

    // Correct signature: sign(message, privateKey, kind)
    // Returns object { result, signature, ... }
    const sigResult = mod.sign(msgBytes, privateKey, 2);

    if (!sigResult || !sigResult.signature) {
        throw new Error("Signing failed: invalid response from library");
    }

    return toHex(sigResult.signature);
};

export const verifySignaturePQC = async (message, signatureHex, publicKeyHex) => {
    const mod = await initDilithium();
    const signature = fromHex(signatureHex);
    const publicKey = fromHex(publicKeyHex);
    const msgBytes = new TextEncoder().encode(message);

    // Mod.verify expects the FULL Signed Message (SM = Signature + Message).
    // If we have a detached signature, we must reconstruct SM.
    const sigLen = signature.length;
    const msgLen = msgBytes.length;
    const SIG_SIZE = 2420; // Dilithium2

    const tryVerify = (smBytes, mBytes) => {
        try {
            const resultObj = mod.verify(smBytes, mBytes, publicKey, 2);
            return resultObj && resultObj.result === 0;
        } catch (e) {
            return e; // Return error to analyze
        }
    };

    // Strategy 1: Detached (Explicit Construction)
    if (sigLen === SIG_SIZE) {
        let sm = new Uint8Array(SIG_SIZE + msgLen);
        sm.set(signature, 0);
        sm.set(msgBytes, SIG_SIZE);

        const res = tryVerify(sm, msgBytes);
        if (res === true) return true;
        // Detached failed, maybe because metadata was signed but we only have signature?
        // Impossible to verify detached signature if we don't know the metadata/extra bytes.
        // We can only hope Strategy 2 (Attached) works if the user passed the full blob.
    }

    // Strategy 2: Attached (Try Original First)
    // If 'signature' is the full SM (Attached), it contains Sig + Msg.
    const resAtt = tryVerify(signature, msgBytes);
    if (resAtt === true) return true;

    // Strategy 3: Extraction Fallback (Handle Metadata/Padding)
    // If the signature blob is larger than Expected (Sig + Msg), it might contain extra data.
    // We trust the Signature Blob as the source of truth for "What was signed".
    if (sigLen > SIG_SIZE) {
        try {
            // 1. Extract the full signed message from the blob
            const extractedMsg = signature.slice(SIG_SIZE);

            // 2. Verify the blob against its OWN content (Self-Consistency)
            // This proves the signer signed 'extractedMsg'.
            const selfCheck = mod.verify(signature, extractedMsg, publicKey, 2);

            if (selfCheck && selfCheck.result === 0) {
                // 3. Compare Extracted Content with Expected Content
                // We check if 'extractedMsg' contains 'msgBytes' (ignoring extra metadata like timestamps)
                // Note: verification matches bytes.

                // Simple Check: Does extracted start with expected?
                // Or is expected inside extracted?
                // Convert to string for safer substring check if text? Or Byte check.
                // Let's use Byte Check: Check if msgBytes is a prefix of extractedMsg.
                let match = true;
                if (extractedMsg.length < msgLen) match = false;
                else {
                    for (let i = 0; i < msgLen; i++) {
                        if (extractedMsg[i] !== msgBytes[i]) {
                            match = false;
                            break;
                        }
                    }
                }

                if (match) {
                    return true;
                } else {
                    console.warn("verifySignaturePQC: Signature valid but content mismatch.");
                }
            }
        } catch (e) {
            console.warn("verifySignaturePQC: Extraction strategy failed", e);
        }
    }

    return false;
};

export const encryptMessagePQC = async (message, publicKeyHex) => {
    // Hybrid Encryption (KEM + AES-GCM):
    // 1. Kyber KEM Encapsulate -> Shared Secret (ss) + Ciphertext (ct)
    // 2. Use ss as AES key
    // 3. Encrypt message with ss (AES-GCM) -> content, iv

    const publicKey = fromHex(publicKeyHex);

    // Encrypt768(pk) returns [ct, ss]
    // ct: Ciphertext (1088 bytes)
    // ss: Shared Secret (32 bytes)
    const kemResult = Encrypt768(publicKey);
    const ct = kemResult[0];
    const ss = kemResult[1];

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

    // Decrypt768(ct, sk) -> returns shared secret (ss)
    const ss = Decrypt768(ct, privateKey);
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
    // 1. Encapsulate a shared secret for the receiver (Kyber)
    const publicKey = fromHex(publicKeyHex);
    // Encrypt768(pk) -> [ct, ss]
    const kemResult = Encrypt768(publicKey);
    const ct = kemResult[0];
    const ss = kemResult[1];

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

    // 1. Decapsulate Shared Secret
    const ss = Decrypt768(ct, privateKey);
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
 *   (In fallback mode, the random key is stored in localStorage under 'safelog_bio_fallback_key')
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
    localStorage.setItem('safelog_bio_fallback_key', fallbackKey);

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
    const fallbackKey = localStorage.getItem('safelog_bio_fallback_key');
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
