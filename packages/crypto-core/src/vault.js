// Vault encryption: the PBKDF2 KDF and the AES-GCM wrapping around it.

import { toB64, fromB64, ENC, DEC } from './encoding.js';

// --- Vault Security ---

// One definition of the vault KDF, shared by the CryptoKey and raw-bits paths
// below so the two can never drift apart.
const VAULT_KDF = {
    name: "PBKDF2",
    iterations: 600000, // OWASP floor for PBKDF2-HMAC-SHA512
    hash: "SHA-512",
};
const VAULT_KEY_BITS = 256;

const vaultKeyMaterial = (password) => crypto.subtle.importKey(
    "raw",
    ENC.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
);

/**
 * The vault key as RAW BYTES. Same KDF and same output as deriveKey() — this
 * just hands back the material instead of a sealed CryptoKey.
 *
 * Exists so a session can be resumed without keeping the PASSWORD anywhere
 * (audit M-4). A non-extractable CryptoKey cannot survive an MV3 service-worker
 * restart — chrome.storage.session is JSON-serialized, not structured-clone —
 * so the extension caches these bytes instead. Strictly less valuable to an
 * attacker than the password: the password is the KDF *input*, survives a salt
 * change, and is the thing a user is likely to have reused elsewhere.
 */
export const deriveVaultKeyBits = async (password, salt) => {
    const material = await vaultKeyMaterial(password);
    const bits = await crypto.subtle.deriveBits(
        { ...VAULT_KDF, salt }, material, VAULT_KEY_BITS
    );
    return new Uint8Array(bits);
};

/** Import raw vault-key bytes as a non-extractable AES-GCM key. */
export const importVaultKey = async (keyBytes) => crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: VAULT_KEY_BITS },
    false,
    ["encrypt", "decrypt"]
);

// Helper to derive key. Composed from the two above rather than calling
// crypto.subtle.deriveKey directly, so there is exactly one KDF in the file and
// the bytes path is provably the same key (byte-compat test pins both).
export async function deriveKey(password, salt) {
    return importVaultKey(await deriveVaultKeyBits(password, salt));
}

export const encryptVault = async (data, password) => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const encodedData = ENC.encode(JSON.stringify(data));

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
    );

    return {
        salt: toB64(salt),
        iv: toB64(iv),
        data: toB64(new Uint8Array(encryptedContent))
    };
};

export const decryptVault = async (encryptedVault, password) => {
    const salt = fromB64(encryptedVault.salt);
    const iv = fromB64(encryptedVault.iv);
    const data = fromB64(encryptedVault.data);

    const key = await deriveKey(password, salt);

    try {
        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );
        return JSON.parse(DEC.decode(decryptedContent));
    } catch {
        throw new Error("Incorrect password or corrupted data");
    }
};

/**
 * Encrypts a data object (vault) with a pre-derived CryptoKey and salt.
 * IV is still random per call — safe to reuse the same key+salt.
 */
export const encryptVaultWithKey = async (data, key, salt) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = ENC.encode(JSON.stringify(data));

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
    );

    return {
        salt: toB64(salt),
        iv: toB64(iv),
        data: toB64(new Uint8Array(encryptedContent))
    };
};

export const decryptVaultWithKey = async (encryptedVault, key) => {
    const iv = fromB64(encryptedVault.iv);
    const data = fromB64(encryptedVault.data);

    try {
        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );
        return JSON.parse(DEC.decode(decryptedContent));
    } catch {
        throw new Error("Decryption failed with cached key");
    }
};
