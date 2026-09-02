// Encryption-key attestation (audit M-1) — SPA-side verification helpers.
// The primitive round-trips live in crypto-core's byte-compat tests; this
// covers the SPA policy layer: status classification and the fail-closed gate.

import { describe, it, expect, beforeEach } from 'vitest';
import {
    generateMlKemKeyPair,
    generateMlDsaKeyPair,
    attestEncryptionKey,
} from '../utils/crypto';
import { attestationStatus, assertSafeRecipient, attestationVerdict, wasEverAttested } from '../services/trustedKeys';
import { safetyNumber } from '../utils/fingerprint';

const makeIdentity = async () => {
    const mldsa = await generateMlDsaKeyPair();
    const mlkem = await generateMlKemKeyPair();
    const attestation = await attestEncryptionKey(mlkem.publicKey, mldsa.privateKey);
    return {
        address: mldsa.publicKey,
        encryption_public_key: mlkem.publicKey,
        encryption_key_attestation: attestation,
        mldsa,
        mlkem,
    };
};

describe('attestationStatus', () => {
    it('classifies a genuine self-attestation as verified', async () => {
        const user = await makeIdentity();
        expect(await attestationStatus(user)).toBe('verified');
    });

    it('classifies a missing attestation as unattested (legacy accounts)', async () => {
        const user = await makeIdentity();
        expect(await attestationStatus({ ...user, encryption_key_attestation: null })).toBe('unattested');
    });

    it('classifies a substituted KEM key as invalid', async () => {
        const user = await makeIdentity();
        const evil = await generateMlKemKeyPair();
        expect(await attestationStatus({ ...user, encryption_public_key: evil.publicKey })).toBe('invalid');
    });
});

describe('assertSafeRecipient (fail-closed gate)', () => {
    beforeEach(() => localStorage.clear());

    it('passes a verified recipient', async () => {
        const user = await makeIdentity();
        expect(await assertSafeRecipient(user)).toBe('verified');
    });

    it('passes an unattested recipient we have never seen attested (legacy account)', async () => {
        const user = await makeIdentity();
        expect(await assertSafeRecipient({ ...user, encryption_key_attestation: null })).toBe('unattested');
    });

    it('throws on an invalid attestation', async () => {
        const user = await makeIdentity();
        const evil = await generateMlKemKeyPair();
        await expect(
            assertSafeRecipient({ ...user, encryption_public_key: evil.publicKey })
        ).rejects.toThrow(/verification failed/i);
    });
});

// The 'unattested' pass-through was a downgrade path: a malicious directory
// could simply OMIT encryption_key_attestation, substitute a KEM key it owns,
// and the M-1 gate would answer 'unattested' and let the send through. The
// allowance is now TOFU-scoped — legacy accounts still work, but a contact
// never silently loses an attestation we have already seen.
describe('attestation downgrade (TOFU-scoped unattested)', () => {
    beforeEach(() => localStorage.clear());

    it('refuses a contact whose attestation disappears after being seen', async () => {
        const user = await makeIdentity();
        expect(await attestationVerdict(user)).toBe('verified');

        // Directory now serves the same identity with the attestation stripped.
        expect(await attestationVerdict({ ...user, encryption_key_attestation: null }))
            .toBe('downgraded');
        await expect(
            assertSafeRecipient({ ...user, encryption_key_attestation: null })
        ).rejects.toThrow(/downgraded/i);
    });

    it('refuses the full attack: attestation stripped AND the key substituted', async () => {
        const user = await makeIdentity();
        await assertSafeRecipient(user);
        const evil = await generateMlKemKeyPair();
        await expect(assertSafeRecipient({
            ...user,
            encryption_public_key: evil.publicKey,
            encryption_key_attestation: null,
        })).rejects.toThrow(/downgraded/i);
    });

    it('still allows a genuine key rotation — the new key arrives attested', async () => {
        const user = await makeIdentity();
        await assertSafeRecipient(user);

        const rotated = await generateMlKemKeyPair();
        const attestation = await attestEncryptionKey(rotated.publicKey, user.mldsa.privateKey);
        expect(await assertSafeRecipient({
            ...user,
            encryption_public_key: rotated.publicKey,
            encryption_key_attestation: attestation,
        })).toBe('verified');
    });

    it('scopes the memory per contact — one attested contact does not gate another', async () => {
        const attested = await makeIdentity();
        const legacy = await makeIdentity();
        await assertSafeRecipient(attested);
        expect(await assertSafeRecipient({ ...legacy, encryption_key_attestation: null }))
            .toBe('unattested');
    });

    it('records on observation, so the messenger needs no confirmation step', async () => {
        const user = await makeIdentity();
        expect(wasEverAttested(user.address)).toBe(false);
        await attestationVerdict(user);
        expect(wasEverAttested(user.address)).toBe(true);
        // Address casing must not create a second, ungated record.
        expect(wasEverAttested(user.address.toUpperCase())).toBe(true);
    });
});

describe('safetyNumber (canonical fingerprint)', () => {
    it('renders 12 groups of 5 digits and is case-insensitive on the address', async () => {
        const user = await makeIdentity();
        const fp = await safetyNumber(user.address, user.encryption_public_key);
        expect(fp).toMatch(/^\d{5}( \d{5}){11}$/);
        const fpUpper = await safetyNumber(user.address.toUpperCase(), user.encryption_public_key);
        expect(fpUpper).toBe(fp);
    });
});
