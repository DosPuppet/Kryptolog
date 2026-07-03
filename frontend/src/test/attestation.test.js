// Encryption-key attestation (audit M-1) — SPA-side verification helpers.
// The primitive round-trips live in crypto-core's byte-compat tests; this
// covers the SPA policy layer: status classification and the fail-closed gate.

import { describe, it, expect } from 'vitest';
import {
    generateMlKemKeyPair,
    generateMlDsaKeyPair,
    attestEncryptionKey,
} from '../utils/crypto';
import { attestationStatus, assertSafeRecipient } from '../services/trustedKeys';
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
    it('passes verified and unattested recipients', async () => {
        const user = await makeIdentity();
        expect(await assertSafeRecipient(user)).toBe('verified');
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

describe('safetyNumber (canonical fingerprint)', () => {
    it('renders 12 groups of 5 digits and is case-insensitive on the address', async () => {
        const user = await makeIdentity();
        const fp = await safetyNumber(user.address, user.encryption_public_key);
        expect(fp).toMatch(/^\d{5}( \d{5}){11}$/);
        const fpUpper = await safetyNumber(user.address.toUpperCase(), user.encryption_public_key);
        expect(fpUpper).toBe(fp);
    });
});
