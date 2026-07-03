// Encrypted entry titles (audit M-3).
//
// Entry names (secret/document names, group channel names) used to be the one
// piece of user content stored in PLAINTEXT server-side. They are now encrypted
// client-side and stored as opaque marker-prefixed blobs; the server never
// learns them. Legacy plaintext names (no marker) still display as-is.
//
// Two shapes:
//
//   Secret titles — encrypted under the SAME per-item AES key ("fileKey") as
//   the item's content, so exactly the people who can read the item can read
//   its name (owner + grantees + multisig signers/recipients via their wraps).
//     "encv1:" + JSON({iv, ciphertext})              (encryptSymmetric output)
//
//   Group names — the group has no single long-lived content key (session keys
//   rotate per message epoch), so the name gets its own key, wrapped for every
//   CURRENT member. Rebuilt (fresh key + wraps) on rename and on membership
//   change, mirroring the message-key rotation semantics.
//     "encg1:" + JSON({ ct: {iv, content}, keys: { address: wrappedKey } })
//                (encryptWithSessionKey / wrapSessionKey outputs)

import {
    encryptSymmetric,
    decryptSymmetric,
    generateSessionKey,
    encryptWithSessionKey,
    decryptWithSessionKey,
    wrapSessionKey,
} from './crypto';

const SECRET_MARKER = 'encv1:';
const GROUP_MARKER = 'encg1:';

export const isEncryptedTitle = (name) =>
    typeof name === 'string' && (name.startsWith(SECRET_MARKER) || name.startsWith(GROUP_MARKER));

// --- Secret titles (under the item's fileKey) ---

export const encryptSecretTitle = async (name, fileKeyHex) =>
    SECRET_MARKER + JSON.stringify(await encryptSymmetric(name, fileKeyHex));

// Returns the plaintext title; legacy plaintext names pass through unchanged.
// A present-but-undecryptable title (no key / wrong key) returns null so the
// caller can render a locked placeholder.
export const decryptSecretTitle = async (name, fileKeyHex) => {
    if (!name || !name.startsWith(SECRET_MARKER)) return name ?? '';
    if (!fileKeyHex) return null;
    try {
        return await decryptSymmetric(JSON.parse(name.slice(SECRET_MARKER.length)), fileKeyHex);
    } catch {
        return null;
    }
};

// --- Group names (own key, wrapped per member) ---

// members: [{ address, encryption_public_key }] — every CURRENT member,
// including the caller. Callers must run the attestation gate on members
// BEFORE this (same rule as wrapping message session keys).
export const encryptGroupName = async (name, members) => {
    const nameKey = await generateSessionKey();
    const ct = await encryptWithSessionKey(name, nameKey);
    const keys = {};
    for (const m of members) {
        if (!m.encryption_public_key) continue;
        keys[m.address.toLowerCase()] = await wrapSessionKey(nameKey, m.encryption_public_key);
    }
    return GROUP_MARKER + JSON.stringify({ ct, keys });
};

// Extracts MY wrapped name-key from the blob (for batch unwrapping), or null.
export const groupNameWrapFor = (name, myAddress) => {
    if (!name || !name.startsWith(GROUP_MARKER)) return null;
    try {
        const { keys } = JSON.parse(name.slice(GROUP_MARKER.length));
        return keys?.[myAddress.toLowerCase()] || null;
    } catch {
        return null;
    }
};

// Decrypts the group name blob with an already-unwrapped nameKey.
// Legacy plaintext names pass through; failures return null (locked placeholder).
export const decryptGroupName = async (name, nameKeyHex) => {
    if (!name || !name.startsWith(GROUP_MARKER)) return name ?? '';
    if (!nameKeyHex) return null;
    try {
        const { ct } = JSON.parse(name.slice(GROUP_MARKER.length));
        return await decryptWithSessionKey(ct, nameKeyHex);
    } catch {
        return null;
    }
};

// Display fallback for a title we can't decrypt (or haven't yet).
export const LOCKED_TITLE = '🔒 Encrypted';
