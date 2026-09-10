// The post-quantum primitives themselves: ML-KEM-768 and ML-DSA-44.
//
// Key generation, signing and verification, and the hybrid KEM + AES-GCM
// message envelope.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';

import { toHex, fromHex, ENC, DEC } from './encoding.js';

// Derive the AES-GCM key from an ML-KEM shared secret via HKDF-SHA-256 with a
// fixed context label (audit S5), instead of importing the raw shared secret as
// the AES key. The ML-KEM secret is already uniform, so this is best-practice
// hygiene + domain binding, not a fix for a weakness. This changes the wire
// format: ciphertext produced before this no longer decrypts (acceptable under
// the clean-cutover stance).
const KEM_KDF_INFO = 'Kryptolog/ML-KEM-768/AES-GCM/v1';
export const kemAesKey = async (sharedSecret, usage) => {
    const ikm = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: ENC.encode(KEM_KDF_INFO) },
        ikm,
        { name: 'AES-GCM', length: 256 },
        false,
        usage
    );
};

// --- PQC Implementations ---

export const generateMlKemKeyPair = async () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    return {
        publicKey: toHex(publicKey),
        privateKey: toHex(secretKey),
    };
};

export const generateMlDsaKeyPair = async () => {
    const { publicKey, secretKey } = ml_dsa44.keygen();
    return {
        publicKey: toHex(publicKey),
        privateKey: toHex(secretKey),
    };
};

// Normalize a stored account to the current field names (compat, v1.2.0).
// Older vaults and exported backups store an identity's keypairs under
// `kyber`/`dilithium` — the pre-standardization names for ML-KEM / ML-DSA. Map
// them to the current `mlkem`/`mldsa` fields on load/import so old data still
// opens; new writes always use the new names. Idempotent, and legacy fields are
// dropped from the result so a subsequent save re-persists only the new shape.
export const normalizeAccount = (account) => {
    if (!account || typeof account !== 'object') return account;
    if (!account.kyber && !account.dilithium) return account; // already current
    const { kyber, dilithium, ...rest } = account;
    return {
        ...rest,
        mlkem: account.mlkem || kyber,
        mldsa: account.mldsa || dilithium,
    };
};

// ML-DSA-44 detached signature over the UTF-8 message bytes.
export const signMessage = async (message, privateKeyHex) => {
    const secretKey = fromHex(privateKeyHex);
    const msgBytes = ENC.encode(message);
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
        const msgBytes = ENC.encode(message);
        // noble API: verify(signature, message, publicKey) -> boolean
        return ml_dsa44.verify(signature, msgBytes, publicKey);
    } catch (e) {
        console.error("verifySignature failed", e);
        return false;
    }
};

export const encryptMessage = async (message, publicKeyHex) => {
    const publicKey = fromHex(publicKeyHex);

    // ML-KEM-768 encapsulate -> { cipherText (1088B), sharedSecret (32B) }
    const { cipherText: ct, sharedSecret: ss } = ml_kem768.encapsulate(publicKey);

    // Derive the AES key from the shared secret via HKDF (audit S5).
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await kemAesKey(new Uint8Array(ss), ["encrypt"]);
    const encodedMsg = ENC.encode(message);

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedMsg
    );

    return {
        kem: toHex(ct),
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
    return DEC.decode(decryptedContent);
};
