/**
 * Every signature is verified against the identity KEY its address names,
 * checked as such, and never against the address itself (crypto-core 3.3.0,
 * audit 2026-10-12 K-10).
 *
 * In 3.x the two are the same string, so nothing else in the suite can tell a
 * verifier that uses the key from one that uses the address. These tests
 * serve keys that do NOT belong to the address, and records with no key at
 * all, which is the only way to see the difference before 4.0.0 makes the
 * address a hash.
 */
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
    messageSigningBody, signMessagePQC, domainSeparate, SIGNING_CONTEXT,
    multisigApprovalMessage, SignedBodyError,
} from '../utils/crypto';
import { makeSigner, directoryRecord } from './identities';
import { identityKeyFor, _resetIdentityKeys } from '../services/identityKeys';
import { verifyMessageAuthenticity } from '../context/messenger/verifyMessage';
import { attestationStatus, attestationVerdict } from '../services/trustedKeys';
import { verifySignedDocument } from '../utils/secretContent';
import { verifyMultisigProofSignatures } from '../components/multisig/proof';

let alice, mallory;

beforeAll(async () => {
    [alice, mallory] = [makeSigner('alice'), makeSigner('mallory')];
}, 60000);

const served = (record) => ({ ok: true, status: 200, json: async () => record });

beforeEach(() => {
    _resetIdentityKeys();
    localStorage.clear();
    global.fetch = vi.fn(async () => served(null));
});

describe('identityKeyFor', () => {
    it('takes a key embedded in a record in hand, without a request', async () => {
        const key = await identityKeyFor(alice.address, { hint: { identity_public_key: alice.identityPublicKey } });
        expect(key).toBe(alice.identityPublicKey);
        expect(global.fetch).not.toHaveBeenCalled();
    });

    it('ignores an embedded key that is not the address\'s, and asks the directory', async () => {
        global.fetch = vi.fn(async () => served({ address: alice.address, identity_public_key: alice.identityPublicKey }));
        const key = await identityKeyFor(alice.address, { hint: { identity_public_key: mallory.identityPublicKey } });
        expect(key).toBe(alice.identityPublicKey);
        expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('refuses a key the directory serves under someone else\'s address, and does not cache it', async () => {
        global.fetch = vi.fn(async () => served({ address: alice.address, identity_public_key: mallory.identityPublicKey }));
        expect(await identityKeyFor(alice.address)).toBeNull();
        expect(await identityKeyFor(alice.address)).toBeNull();
        expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it('shares one request between concurrent lookups, and caches what checked out', async () => {
        global.fetch = vi.fn(async () => served({ address: alice.address, identity_public_key: alice.identityPublicKey }));
        const keys = await Promise.all([1, 2, 3].map(() => identityKeyFor(alice.address)));
        expect(keys).toEqual([alice.identityPublicKey, alice.identityPublicKey, alice.identityPublicKey]);
        await identityKeyFor(alice.address);
        expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('does not cache a failed lookup', async () => {
        global.fetch = vi.fn(async () => { throw new Error('offline'); });
        expect(await identityKeyFor(alice.address)).toBeNull();
        global.fetch = vi.fn(async () => served({ address: alice.address, identity_public_key: alice.identityPublicKey }));
        expect(await identityKeyFor(alice.address)).toBe(alice.identityPublicKey);
    });
});

describe('message verification', () => {
    const dmSignedBy = async (who, to, extra = {}) => {
        const signed = { sid: 's1', ts: 1760264400000, seq: 0, ct: 'deadbeef', keys: null };
        const body = await messageSigningBody({ from: who.address, conv: to, ...signed });
        return { v: 1, ...signed, sig: await signMessagePQC(body, who.seed), ...extra };
    };

    it('refuses a message whose sender record carries a key the address does not name', async () => {
        const payload = await dmSignedBy(alice, mallory.address);
        const row = { sender_address: alice.address, recipient_address: mallory.address };
        // Served Mallory's key: the address check refuses it, and the lookup it
        // falls back to (here: nothing) does not make it verify either.
        expect(await verifyMessageAuthenticity(
            { ...row, sender: { identity_public_key: mallory.identityPublicKey } }, payload, 'dm',
        )).toBe(false);
        expect(await verifyMessageAuthenticity(
            { ...row, sender: { identity_public_key: alice.identityPublicKey } }, payload, 'dm',
        )).toBe(true);
    });

    // Channel ids are minted by the server. A DM's signed body is conv=<to>,
    // gid= — exactly what a gid-less group message in a channel whose id is
    // that address would rebuild.
    it('refuses a DM replayed into a group whose channel id is the recipient\'s address', async () => {
        const bob = 'b0'.repeat(48);
        const payload = await dmSignedBy(alice, bob);
        const hint = { identity_public_key: alice.identityPublicKey };
        expect(await verifyMessageAuthenticity(
            { sender_address: alice.address, sender: hint, recipient_address: bob }, payload, 'dm',
        )).toBe(true);
        expect(await verifyMessageAuthenticity(
            { sender_address: alice.address, sender: hint, channel_id: bob }, payload, 'group',
        )).toBe(false);
    });

    // The mirror image — a group message in a channel whose id is an address,
    // replayed as a DM to that address — cannot even be SIGNED since 4.0.0: a
    // channel id is at most 64 characters and an address exactly 96 hex, so no
    // value is both. The gid rule above stays as the second layer.
    it('cannot sign a group message whose channel id is an address', async () => {
        const signed = { sid: 's1', ts: 1760264400000, seq: 0, ct: 'deadbeef', keys: null };
        await expect(messageSigningBody({
            from: alice.address, conv: mallory.address, gid: mallory.address, ...signed,
        })).rejects.toThrow(SignedBodyError);
    });
});

describe('encryption-key attestation', () => {
    const contact = (identity) => directoryRecord(identity);

    it('is invalid when the identity key served is not the address\'s, even one that signed it', async () => {
        // Mallory attests her own KEM key, and the directory serves it — with
        // her identity key — under Alice's address.
        const forged = { ...(await contact(mallory)), address: alice.address };
        expect(await attestationStatus(forged)).toBe('invalid');
    });

    it('treats a record served without its identity key like one without an attestation', async () => {
        const user = await contact(alice);
        expect(await attestationVerdict(user)).toBe('verified');
        const stripped = { ...user, identity_public_key: undefined };
        expect(await attestationStatus(stripped)).toBe('unattested');
        // ...including the downgrade rule: seen attested once, never silently not.
        expect(await attestationVerdict(stripped)).toBe('downgraded');
    });
});

describe('signed documents and proofs', () => {
    const contentSig = (who, content) =>
        signMessagePQC(domainSeparate(SIGNING_CONTEXT.CONTENT, content), who.seed);

    it('a signed document names the address its embedded key names', async () => {
        const doc = { content: 'doc', signature: await contentSig(alice, 'doc'), signerPublicKey: alice.identityPublicKey };
        expect(await verifySignedDocument(doc)).toEqual({ valid: true, signerAddress: alice.address });
        expect(await verifySignedDocument({ ...doc, signerPublicKey: 'not a key' }))
            .toEqual({ valid: false, signerAddress: null });
    });

    it('a proof entry verifies only with a key its address names — never with the address alone', async () => {
        const approval = multisigApprovalMessage(7, 9, 'ab'.repeat(48));
        const { signMessage } = await import('../utils/crypto');
        const entry = {
            address: alice.address,
            identity_public_key: alice.identityPublicKey,
            signature: await signMessage(approval, alice.seed),
            algorithm: 'MLDSA65-ECDSA-P384-SHA512',
            role: 'signer',
        };
        const proof = (signatures) => ({
            workflow: { id: 7, secret_id: 9 },
            version: '3.0',
            document: { content: 'doc', ciphertext_sha384: 'ab'.repeat(48) },
            signatures,
        });
        const [ok, keyless, wrongKey] = await verifyMultisigProofSignatures(proof([
            entry,
            { ...entry, identity_public_key: undefined },
            { ...entry, identity_public_key: mallory.identityPublicKey },
        ]));
        expect([ok.valid, keyless.valid, wrongKey.valid]).toEqual([true, false, false]);
    });

    it('refuses a proof made before 5.0.0 by name, not as a set of failed signatures', async () => {
        for (const version of ['1.1', '2.0']) {
            const old = { version, workflow: {}, document: {}, signatures: [] };
            await expect(verifyMultisigProofSignatures(old)).rejects.toThrow(/older Kryptolog version/);
        }
    });
});

// The guarantee above holds only if nothing goes around it.
const sourceFiles = (dir) => readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === 'test' ? [] : sourceFiles(path);
    return /\.(js|jsx)$/.test(name) ? [path] : [];
});

describe('no verification goes around the identity key', () => {
    it('nothing in the app calls the raw signature verifier', () => {
        const offenders = sourceFiles(join(__dirname, '..'))
            .filter((f) => /\bverifySignature(PQC)?\s*\(|verifySignature as\b/.test(readFileSync(f, 'utf8')));
        expect(offenders).toEqual([]);
    });
});
