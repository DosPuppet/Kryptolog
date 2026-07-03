// TOFU (trust-on-first-use) store for contacts' encryption keys — audit S1.
//
// Because the server is the key directory, the only meaningful defense against
// a key swap is client-side: remember the encryption key we first saw for each
// contact and flag any later change so the user can verify it out of band
// before trusting the new key. A server-pushed "key changed" alert would be
// worthless here — a malicious server simply wouldn't send it. Stored locally,
// never transmitted.

import { verifyEncryptionKeyAttestation } from '../utils/crypto';

const STORE_KEY = 'kryptolog_trusted_keys';

const load = () => {
    try {
        return JSON.parse(localStorage.getItem(STORE_KEY)) || {};
    } catch {
        return {};
    }
};

const save = (map) => {
    try {
        localStorage.setItem(STORE_KEY, JSON.stringify(map));
    } catch {
        /* localStorage full/unavailable — best effort */
    }
};

const norm = (address) => (address || '').toLowerCase();

// Returns 'new' (never seen), 'unchanged', or 'changed'.
export const checkContactKey = (address, encryptionPublicKey) => {
    if (!encryptionPublicKey) return 'unchanged'; // nothing to compare against
    const rec = load()[norm(address)];
    if (!rec) return 'new';
    return rec.key === encryptionPublicKey ? 'unchanged' : 'changed';
};

// Record / accept a contact's current key (first use, or after the user
// confirms a change). Preserves the original firstSeen timestamp.
export const trustContactKey = (address, encryptionPublicKey) => {
    if (!encryptionPublicKey) return;
    const map = load();
    const a = norm(address);
    const existing = map[a];
    map[a] = {
        key: encryptionPublicKey,
        firstSeen: existing?.firstSeen || Date.now(),
        updatedAt: Date.now(),
    };
    save(map);
};

export const getTrustedKey = (address) => load()[norm(address)] || null;

// --- Encryption-key attestation (audit M-1) ---
// TOFU above detects a key CHANGE; the attestation proves the key BINDING:
// the contact self-signed their ML-KEM key with their identity (ML-DSA) key,
// and the address IS that identity key, so verification needs no trusted
// third party. A directory that substitutes a KEM key it controls cannot
// forge this signature.

// 'verified'   — attestation present and cryptographically valid
// 'unattested' — no attestation (account predates the feature / old client)
// 'invalid'    — attestation present but WRONG: treat as an active key-swap
//                attack and refuse to encrypt to this key.
export const attestationStatus = async (user) => {
    if (!user?.encryption_public_key || !user?.encryption_key_attestation) return 'unattested';
    const ok = await verifyEncryptionKeyAttestation(
        norm(user.address),
        user.encryption_public_key,
        user.encryption_key_attestation,
    );
    return ok ? 'verified' : 'invalid';
};

// Fail-closed guard for every place we wrap a key to a contact. Throws on an
// invalid attestation; passes 'verified' and (for compat) 'unattested'.
export const assertSafeRecipient = async (user) => {
    const status = await attestationStatus(user);
    if (status === 'invalid') {
        throw new Error(
            `Key verification failed for ${user.username || user.address?.slice(0, 12) + '…'}: ` +
            'their encryption key does not match their identity signature. ' +
            'The directory may be serving a substituted key — do not send.'
        );
    }
    return status;
};
