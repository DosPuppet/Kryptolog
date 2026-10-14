// How big the PQC envelopes actually are, pinned against the server's bounds.
//
// Three fields in this app hold envelopes rather than user text: a group name
// (a per-member key-wrap map, audit M-3), a DM's content, and a group
// message's content. Their size is set by composite signatures, CatKDF-wrapped
// session keys and the member count — not by what anyone typed.
//
// `backend/schemas.py` budgets for each of them using costs measured HERE. The
// two live in different languages in different packages, so nothing but this
// test keeps them together. Budgeting them as text once made group creation
// impossible, capped a group at nine members and a first DM at ~160
// characters, each surfacing as a bare 422 in the browser.
//
// If a primitive change inflates an envelope, this fails on the producing
// side and names the constant to raise, instead of appearing as an
// unexplained rejection in someone's messenger.
import { describe, it, expect } from 'vitest';
import {
    generateSessionKey,
    encryptWithSessionKey,
    wrapSessionKey,
    generateEncryptionKeyPair,
    generateIdentityKeyPair,
    addressOf,
    signMessage,
    messageSigningBody,
} from '../src/index.js';

// Must match backend/schemas.py. Raising one means raising the other.
const SERVER = {
    MAX_GROUP_MEMBERS: 50,
    KEY_WRAP_CHARS_PER_MEMBER: 1_946,
    SIGNATURE_CHARS: 4_552,
    WRAPPED_KEY_CHARS: 1_850,
    MAX_MESSAGE_TEXT_CHARS: 10_000,
    MAX_GROUP_NAME_LEN: 97_300,
    MAX_DM_CONTENT_LEN: 49_276,
    MAX_GROUP_MESSAGE_CONTENT_LEN: 142_876,
};

// One identity's worth of real key material, generated once — keygen is the
// slow part and only the LENGTHS matter here.
let kem, dsa;
const identity = async () => {
    kem ??= generateEncryptionKeyPair();
    dsa ??= generateIdentityKeyPair();
    return { kem, dsa };
};

// The longest name the SPA's create-group input accepts (maxLength={100}),
// so the fixed part of the blob is measured at its worst case too.
const LONGEST_NAME = 'T'.repeat(100);

// Distinct member addresses of the correct length, without paying for 50
// keygens: every address is the same size (a SHA-384, 96 hex).
const membersOfSize = (n, dsa, kem) =>
    Array.from({ length: n }, (_, i) => ({
        address: addressOf(dsa.publicKey).slice(0, -4) + String(i).padStart(4, '0'),
        encryptionPublicKey: kem.publicKey,
    }));

// Mirrors frontend/src/utils/titles.js `encryptGroupName`. Kept here rather
// than imported because the SPA is not a dependency of this package.
const buildGroupNameBlob = async (name, members) => {
    const nameKey = await generateSessionKey();
    const ct = await encryptWithSessionKey(name, nameKey);
    const keys = {};
    for (const m of members) {
        keys[m.address.toLowerCase()] = await wrapSessionKey(nameKey, m.encryptionPublicKey);
    }
    return 'encg1:' + JSON.stringify({ ct, keys });
};

describe('encrypted group name size', () => {
    // The unit every other bound is built from, measured directly: a wrap is
    // JSON {v, alg, kid, kem, iv, encKey}, ~1 790 characters under 5.0.0.
    it('one wrapped session key fits WRAPPED_KEY_CHARS', async () => {
        const { kem } = await identity();
        const wrapped = JSON.stringify(await wrapSessionKey(await generateSessionKey(), kem.publicKey));
        expect(wrapped.length).toBeLessThanOrEqual(SERVER.WRAPPED_KEY_CHARS);
        expect(SERVER.KEY_WRAP_CHARS_PER_MEMBER).toBe(96 + SERVER.WRAPPED_KEY_CHARS);
    });

    it('costs less per member than the server budgets for', async () => {
        const { kem, dsa } = await identity();
        const members = membersOfSize(3, dsa, kem);

        const one = await buildGroupNameBlob(LONGEST_NAME, members.slice(0, 1));
        const three = await buildGroupNameBlob(LONGEST_NAME, members);

        // The blob is affine in the member count: a fixed envelope (marker,
        // ciphertext, JSON punctuation) plus a per-member wrap. Separate the
        // two, because only the marginal cost is what the server's constant
        // budgets for — this is the number to raise there if it fails.
        const perMember = (three.length - one.length) / 2;
        const envelope = one.length - perMember;

        expect(perMember).toBeLessThanOrEqual(SERVER.KEY_WRAP_CHARS_PER_MEMBER);
        // The envelope rides on top of the budget, so it has to fit in the
        // rounding headroom rather than being covered by it.
        expect(envelope + SERVER.MAX_GROUP_MEMBERS * perMember).toBeLessThanOrEqual(
            SERVER.MAX_GROUP_NAME_LEN
        );
    }, 30_000);

    it('fits the server bound at the full member cap', async () => {
        const { kem, dsa } = await identity();
        const blob = await buildGroupNameBlob(
            LONGEST_NAME,
            membersOfSize(SERVER.MAX_GROUP_MEMBERS, dsa, kem)
        );
        expect(blob.length).toBeLessThanOrEqual(SERVER.MAX_GROUP_NAME_LEN);
    }, 30_000);
});

// The largest values 3.0.0 payloads carry for the replay fields (K-06): a
// millisecond clock for centuries to come, and a session longer than any
// rotation allows.
const TS = 9_999_999_999_999;
const SEQ = 999_999;

describe('signed message envelope size', () => {
    // Mirrors MessengerContext's DM send: the FIRST message of a conversation
    // mints a session and carries two wraps; later ones carry keys: null.
    const buildDm = async (text, { rekey }) => {
        const { kem, dsa } = await identity();
        const from = addressOf(dsa.publicKey);
        const conv = from.slice(0, -4) + 'beef';
        const sid = crypto.randomUUID();
        const sKey = await generateSessionKey();
        const keys = rekey
            ? {
                  recip: await wrapSessionKey(sKey, kem.publicKey),
                  sender: await wrapSessionKey(sKey, kem.publicKey),
              }
            : null;
        const ct = await encryptWithSessionKey(text, sKey);
        const sig = await signMessage(
            await messageSigningBody({ from, conv, sid, keys, ct, ts: TS, seq: SEQ }),
            dsa.seed
        );
        return JSON.stringify({ v: 1, sid, ts: TS, seq: SEQ, keys, ct, sig });
    };

    it('fits a full-length first message, which carries two wrapped keys', async () => {
        const wire = await buildDm('x'.repeat(SERVER.MAX_MESSAGE_TEXT_CHARS), { rekey: true });
        expect(wire.length).toBeLessThanOrEqual(SERVER.MAX_DM_CONTENT_LEN);
    }, 30_000);

    // The text cap counts JavaScript string length (UTF-16 units), but the
    // budget used to assume one BYTE per unit. A full-length message of CJK or
    // accented text is 2-3x that, so it blew MAX_DM_CONTENT_LEN and came back
    // as a bare 422 well below the advertised 10 000 characters. Worst case is
    // 3 bytes per unit: a BMP character is one unit and up to 3 bytes, while an
    // astral character (emoji) is 4 bytes across TWO units, so it is cheaper
    // per unit rather than dearer.
    it.each([
        ['CJK (3 bytes per unit — the worst case)', '\u6f22'],
        ['accented Latin (2 bytes per unit)', '\u00e9'],
        ['emoji (4 bytes, but 2 units each)', '\u{1f512}'],
    ])('fits a full-length first message of %s', async (_label, char) => {
        const text = char.repeat(SERVER.MAX_MESSAGE_TEXT_CHARS / char.length);
        expect(text.length).toBe(SERVER.MAX_MESSAGE_TEXT_CHARS);
        const wire = await buildDm(text, { rekey: true });
        expect(wire.length).toBeLessThanOrEqual(SERVER.MAX_DM_CONTENT_LEN);
    }, 30_000);

    it('spends most of a short first message on the signature and wraps', async () => {
        // The point of the bound: an empty-ish first message is already ~8 000
        // chars, which is why a 10 000 cap once left almost no room for text.
        const wire = await buildDm('hi', { rekey: true });
        expect(wire.length).toBeGreaterThan(SERVER.SIGNATURE_CHARS);
        expect(wire.length).toBeLessThanOrEqual(SERVER.MAX_DM_CONTENT_LEN);
    }, 30_000);

    it('fits a full-group rekey message at the member cap', async () => {
        const { kem, dsa } = await identity();
        const members = membersOfSize(SERVER.MAX_GROUP_MEMBERS, dsa, kem);
        const gid = crypto.randomUUID();
        const sid = crypto.randomUUID();
        const sKey = await generateSessionKey();

        const keys = {};
        for (const m of members) keys[m.address] = await wrapSessionKey(sKey, m.encryptionPublicKey);

        const ct = await encryptWithSessionKey('x'.repeat(SERVER.MAX_MESSAGE_TEXT_CHARS), sKey);
        const sig = await signMessage(
            await messageSigningBody({ from: members[0].address, conv: gid, gid, sid, keys, ct, ts: TS, seq: SEQ }),
            dsa.seed
        );
        const wire = JSON.stringify({ v: 2, sid, gid, ts: TS, seq: SEQ, keys, ct, sig });

        expect(wire.length).toBeLessThanOrEqual(SERVER.MAX_GROUP_MESSAGE_CONTENT_LEN);
    }, 60_000);
});
