// Encrypted entry titles (audit M-3) — format round-trips, legacy passthrough,
// and the group name blob's member-wrap semantics.

import { describe, it, expect } from 'vitest';
import { generateSymmetricKey, generateMlKemKeyPair, unwrapSessionKey } from '../utils/crypto';
import {
    encryptSecretTitle,
    decryptSecretTitle,
    encryptGroupName,
    decryptGroupName,
    groupNameWrapFor,
    isEncryptedTitle,
    LOCKED_TITLE,
} from '../utils/titles';

describe('secret titles (encv1, under the item fileKey)', () => {
    it('round-trips and is marker-prefixed ciphertext', async () => {
        const fileKey = await generateSymmetricKey();
        const blob = await encryptSecretTitle('My bank codes', fileKey);
        expect(blob.startsWith('encv1:')).toBe(true);
        expect(blob).not.toContain('bank');
        expect(isEncryptedTitle(blob)).toBe(true);
        expect(await decryptSecretTitle(blob, fileKey)).toBe('My bank codes');
    });

    it('legacy plaintext names pass through unchanged', async () => {
        expect(isEncryptedTitle('Old plaintext name')).toBe(false);
        expect(await decryptSecretTitle('Old plaintext name', null)).toBe('Old plaintext name');
    });

    it('returns null (locked) without the right key', async () => {
        const blob = await encryptSecretTitle('secret', await generateSymmetricKey());
        expect(await decryptSecretTitle(blob, null)).toBe(null);
        expect(await decryptSecretTitle(blob, await generateSymmetricKey())).toBe(null);
        expect(LOCKED_TITLE).toBeTruthy();
    });
});

describe('group names (encg1, own key wrapped per member)', () => {
    it('every member can unwrap and decrypt; non-members cannot', async () => {
        const alice = await generateMlKemKeyPair();
        const bob = await generateMlKemKeyPair();
        const mallory = await generateMlKemKeyPair();

        const blob = await encryptGroupName('Ops war room', [
            { address: 'ALICE_ADDR', encryption_public_key: alice.publicKey },
            { address: 'bob_addr', encryption_public_key: bob.publicKey },
        ]);
        expect(blob.startsWith('encg1:')).toBe(true);
        expect(blob).not.toContain('war room');

        // Address lookup is case-insensitive (wraps are stored lowercase).
        for (const [addr, kp] of [['alice_addr', alice], ['BOB_ADDR', bob]]) {
            const wrap = groupNameWrapFor(blob, addr);
            expect(wrap).toBeTruthy();
            const nameKey = await unwrapSessionKey(wrap, kp.privateKey);
            expect(await decryptGroupName(blob, nameKey)).toBe('Ops war room');
        }

        // A non-member has no wrap at all.
        expect(groupNameWrapFor(blob, 'mallory_addr')).toBe(null);
        void mallory;
    });

    it('legacy plaintext group names pass through', async () => {
        expect(await decryptGroupName('Old Group', null)).toBe('Old Group');
        expect(groupNameWrapFor('Old Group', 'anyone')).toBe(null);
    });

    it('re-encryption mints a fresh key: old wraps are useless for the new blob', async () => {
        const alice = await generateMlKemKeyPair();
        const members = [{ address: 'a', encryption_public_key: alice.publicKey }];
        const blob1 = await encryptGroupName('Name v1', members);
        const blob2 = await encryptGroupName('Name v2', members);
        const key1 = await unwrapSessionKey(groupNameWrapFor(blob1, 'a'), alice.privateKey);
        // The old key does not decrypt the new blob (fresh key per rebuild).
        expect(await decryptGroupName(blob2, key1)).toBe(null);
    });
});
