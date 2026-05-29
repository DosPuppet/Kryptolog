import KyberPkg from 'crystals-kyber';
import { createDilithium } from 'dilithium-crystals-js';
import { Buffer } from 'buffer';

const { KeyGen768, Encrypt768, Decrypt768 } = KyberPkg;

// Ensure initialization
let dilithium = null;
const initDilithium = async () => {
    if (!dilithium) {
        dilithium = await createDilithium();
    }
    return dilithium;
};

// Helper: Uint8Array/Array <-> Hex
const toHex = (arr) => Buffer.from(arr).toString('hex');
const fromHex = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));

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
        // Use level 2 (matches standard expectation in library apparently)
        const { publicKey, privateKey } = mod.generateKeys(2);
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
        id: crypto.randomUUID(),
        name,
        kyber,
        dilithium,
        createdAt: Date.now(),
    };
};

export const signMessage = async (message, privateKeyHex) => {
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

export const verifySignature = async (message, signatureHex, publicKeyHex) => {
    const mod = await initDilithium();
    const signature = fromHex(signatureHex);
    const publicKey = fromHex(publicKeyHex);
    const msgBytes = new TextEncoder().encode(message);

    // Correct signature: verify(signature, message, publicKey, kind)
    // Returns object { result, ... } where result 0 is success
    const resultObj = mod.verify(signature, msgBytes, publicKey, 2);

    return resultObj && resultObj.result === 0;
};

export const encryptMessage = async (message, publicKeyHex) => {
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

export const decryptMessage = async (encryptedData, privateKeyHex) => {
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

// --- Session Key Architecture (Signal-Lite) ---

export const generateSessionKey = () => {
    // Generate a random 32-byte key for AES-256
    const key = crypto.getRandomValues(new Uint8Array(32));
    return toHex(key);
};

export const encryptSessionKey = (sessionKeyHex, publicKeyHex) => {
    // Wrap the session key using Kyber
    // Input: 32-byte key (hex). Output: Kyber Ciphertext (hex) + AES-encrypted key (hex)?
    // Problem: Kyber Decapsulation produces a SHARED SECRET, not an arbitrary buffer decryption.
    // Kyber is a KEM.
    // Standard KEM:
    // Sender: (ss, ct) = Encaps(pk)
    // Receiver: ss = Decaps(ct, sk)
    // We want to transmit 'SessionKey'.
    // So we use 'ss' to AES-encrypt 'SessionKey'.
    // Packet: { kem: ct, iv: ..., encKey: AES(SessionKey, ss) }

    // BUT! We can just use the 'ss' AS the Session Key?
    // If we do that, we can't control it. Sender needs to send the SAME key to multiple recipients (Self + Other).
    // So Sender generates Random SessionKey.
    // Sender -> Recipient: 
    //    1. (ss_r, ct_r) = Encaps(pk_r)
    //    2. enc_k_r = AES(SessionKey, key=ss_r)
    //    3. Header: { kem: ct_r, iv: ..., key: enc_k_r }

    try {
        const pk = fromHex(publicKeyHex);
        const [ct, ss] = Encrypt768(pk); // ct=1088 bytes, ss=32 bytes

        // Use SS to encrypt the actual SessionKey
        const sessionKey = fromHex(sessionKeyHex);
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Import SS as Key
        // Note: ss is from Kyber, usually raw bytes.
        // We can import directly.
        // Sync import? importKey is async.
        // We need to implement this async inside.
        // But Kyber is sync (in this lib).

        // Wait, Encrypt768 output format?
        // crystal-kyber-js returns Uint8Array usually.

        return { ct: toHex(ct), ss: toHex(ss) };
    } catch (e) {
        throw new Error("Session Key Encapsulation failed");
    }
};

// Helper to encrypt the SessionKey blob using the KEM-derived secret
// This needs to be async because of subtle crypto
export const wrapSessionKey = async (sessionKeyHex, recipientPubKeyHex) => {
    const pk = fromHex(recipientPubKeyHex);
    const [ct, ss] = Encrypt768(pk); // KEM

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

    // Decapsulate to get SS
    const ss = Decrypt768(ct, sk);

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
