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
// Separate store from STORE_KEY on purpose: that one records keys the user
// explicitly accepted in the share flow, this one records what we observed
// automatically. Mixing them would make checkContactKey see half-populated
// records and report spurious key changes.
const ATTEST_KEY = 'kryptolog_attested_contacts';

const load = (store) => {
    try {
        return JSON.parse(localStorage.getItem(store)) || {};
    } catch {
        return {};
    }
};

const save = (store, map) => {
    try {
        localStorage.setItem(store, JSON.stringify(map));
    } catch {
        /* localStorage full/unavailable — best effort */
    }
};

const norm = (address) => (address || '').toLowerCase();

// Returns 'new' (never seen), 'unchanged', or 'changed'.
export const checkContactKey = (address, encryptionPublicKey) => {
    if (!encryptionPublicKey) return 'unchanged'; // nothing to compare against
    const rec = load(STORE_KEY)[norm(address)];
    if (!rec) return 'new';
    return rec.key === encryptionPublicKey ? 'unchanged' : 'changed';
};

// Record / accept a contact's current key (first use, or after the user
// confirms a change). Preserves the original firstSeen timestamp.
export const trustContactKey = (address, encryptionPublicKey) => {
    if (!encryptionPublicKey) return;
    const map = load(STORE_KEY);
    const a = norm(address);
    const existing = map[a];
    map[a] = {
        key: encryptionPublicKey,
        firstSeen: existing?.firstSeen || Date.now(),
        updatedAt: Date.now(),
    };
    save(STORE_KEY, map);
};

// The contacts this device has pinned, most recently confirmed first. The
// share dialog's default list (audit 2026-10-12 K-13): the directory no longer
// answers an empty search, and the people a user shares with are the ones this
// store already knows — without asking the server who exists.
export const recentContacts = (limit = 10) =>
    Object.entries(load(STORE_KEY))
        .sort(([, a], [, b]) => (b.updatedAt || 0) - (a.updatedAt || 0))
        .slice(0, limit)
        .map(([address]) => address);

// The TOFU verdict, acted on: a first sighting is pinned, a change refuses.
//
// The store used to be consulted only by the share dialog, so a contact whose
// key changed went on receiving messages with nothing on screen to say so
// (audit 2026-10-12 K-05). Every send path now goes through this, and the
// conversation offers the confirmation (KeyTrustPanel) — so the stop does not
// depend on the reader noticing a banner. Returns the state it acted on.
export const pinContactKey = (user) => {
    const state = checkContactKey(user?.address, user?.encryption_public_key);
    if (state === 'new') trustContactKey(user.address, user.encryption_public_key);
    return state;
};

export const assertKeyUnchanged = (user) => {
    if (pinContactKey(user) === 'changed') {
        throw new Error(
            `${label(user)}'s encryption key changed. Nothing was sent: compare ` +
            'the safety number in the conversation and confirm the new key first.'
        );
    }
};

// --- Trust stores in a backup (audit 2026-10-12 K-05) ---
//
// Both stores live in localStorage only, so a new device or a restored backup
// started blind: every contact was 'new' again and a key swapped meanwhile was
// pinned without a word. They travel with the vault now. Merged, with the LOCAL
// record winning on conflict — an import must never be able to overwrite a key
// this device already pinned, or restoring an old (or planted) backup would be
// a way to make a changed key look unchanged.
export const exportTrustStores = () => ({ keys: load(STORE_KEY), attested: load(ATTEST_KEY) });

const isRecord = (r) => !!r && typeof r === 'object' && typeof r.key === 'string';

export const importTrustStores = (data) => {
    if (!data || typeof data !== 'object') return;
    for (const [store, incoming] of [[STORE_KEY, data.keys], [ATTEST_KEY, data.attested]]) {
        if (!incoming || typeof incoming !== 'object') continue;
        const map = load(store);
        for (const [address, rec] of Object.entries(incoming)) {
            const a = norm(address);
            if (a && isRecord(rec) && !map[a]) map[a] = rec;
        }
        save(store, map);
    }
};

// --- Encryption-key attestation (audit M-1) ---
// TOFU above detects a key CHANGE; the attestation proves the key BINDING:
// the contact self-signed their ML-KEM key with their identity (ML-DSA) key,
// and the address IS that identity key, so verification needs no trusted
// third party. A directory that substitutes a KEM key it controls cannot
// forge this signature.

// 'verified'   — attestation present and cryptographically valid
// 'unattested' — no attestation. Refused by every gate since crypto-core 3.0.0
//                (audit 2026-10-12 K-04); kept as a distinct verdict so the UI
//                can say WHY a contact cannot be written to.
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

// --- Attestation downgrade (the 'unattested' hole) ---
//
// 'unattested' has to keep passing: accounts predating M-1, and custody paths
// whose client cannot produce an attestation, would otherwise become
// unmessageable. But an allowance a MALICIOUS DIRECTORY can trigger at will is
// not compatibility, it's a bypass — the server omits encryption_key_attestation
// from its response, substitutes a KEM key it owns, and the gate built to stop
// exactly that answers 'unattested' and waves it through. The attestation was
// only ever as strong as the client's willingness to require it.
//
// So the allowance is TOFU-scoped, the same shape this module already uses for
// keys: once a contact has been seen attested, they never silently go back. A
// genuine key rotation still passes (the new key arrives attested too); only a
// DISAPPEARING attestation is refused. That leaves legacy accounts working while
// removing the server's ability to choose which check applies.
//
// Recording happens on observation, not on user confirmation — that is what
// trust-on-first-use means, and the messenger has no confirmation step to hang
// it on. First contact with an unattested account is still trusted blindly;
// nothing here can fix that without an out-of-band channel (that is what the
// safety number in utils/fingerprint.js is for).
const rememberAttested = (address, encryptionPublicKey) => {
    const a = norm(address);
    // Never key a record on the empty string: every address-less object would
    // then share one record, and one verified sighting would mark them all.
    // Unreachable today (attestationStatus can't verify without an address),
    // kept so a future caller can't make it reachable.
    if (!a) return;
    const map = load(ATTEST_KEY);
    map[a] = {
        key: encryptionPublicKey,
        firstSeen: map[a]?.firstSeen || Date.now(),
        updatedAt: Date.now(),
    };
    save(ATTEST_KEY, map);
};

export const wasEverAttested = (address) => Boolean(load(ATTEST_KEY)[norm(address)]);

// TOFU-aware verdict, and the one every gate should use. Same values as
// attestationStatus plus:
// 'downgraded' — previously seen attested, now served with no attestation.
//                Treated exactly like 'invalid': it is what a key swap by
//                omission looks like.
export const attestationVerdict = async (user) => {
    const status = await attestationStatus(user);
    if (status === 'verified') {
        rememberAttested(user.address, user.encryption_public_key);
        return 'verified';
    }
    if (status === 'unattested' && wasEverAttested(user.address)) return 'downgraded';
    return status;
};

const label = (user) => user?.username || `${user?.address?.slice(0, 12)}…`;

// Fail-closed guard for every place we wrap a key to a contact. Passes only
// 'verified'.
//
// 'unattested' used to pass, for accounts that predated attestations — which
// left the server free to substitute the key of any contact a user had never
// seen attested, by simply omitting the attestation (audit 2026-10-12 K-04).
// The crypto-core 3.0.0 cutover wiped every such account, and the server now
// refuses a key without one, so a missing attestation can only mean the
// directory is not serving what the contact signed.
export const assertSafeRecipient = async (user) => {
    const verdict = await attestationVerdict(user);
    if (verdict === 'unattested') {
        throw new Error(
            `No key attestation for ${label(user)}: their encryption key is not ` +
            'signed by their identity, so it cannot be told apart from a ' +
            'substituted one — do not send.'
        );
    }
    if (verdict === 'invalid') {
        throw new Error(
            `Key verification failed for ${label(user)}: ` +
            'their encryption key does not match their identity signature. ' +
            'The directory may be serving a substituted key — do not send.'
        );
    }
    if (verdict === 'downgraded') {
        throw new Error(
            `Key verification downgraded for ${label(user)}: they were previously ` +
            'attested, and their key is now served with no attestation at all. ' +
            'That is what a key swap by omission looks like — verify their safety ' +
            'number out of band before sending.'
        );
    }
    return verdict;
};
