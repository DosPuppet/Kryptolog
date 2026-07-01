// TOFU (trust-on-first-use) store for contacts' encryption keys — audit S1.
//
// Because the server is the key directory, the only meaningful defense against
// a key swap is client-side: remember the encryption key we first saw for each
// contact and flag any later change so the user can verify it out of band
// before trusting the new key. A server-pushed "key changed" alert would be
// worthless here — a malicious server simply wouldn't send it. Stored locally,
// never transmitted.

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
