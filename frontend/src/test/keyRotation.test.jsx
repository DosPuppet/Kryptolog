/**
 * A contact's key replaced by a SIGNED ROTATION (crypto-core 5.1.0): the
 * conversation says so, with the date — and still stops the send until the
 * new safety number is confirmed (K-05 unchanged, decided 2026-10-14). The
 * rotation is signed by the identity key, like the attestation, so it can
 * explain a change but cannot vouch for one.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import KeyTrustPanel from '../components/messenger/KeyTrustPanel';
import { trustContactKey, checkContactKey } from '../services/trustedKeys';
import { generateEncryptionKeyPair, encryptionKeyId, signKeyRotation, KEM_ALG } from '../utils/crypto';
import { makeSigner, directoryRecord } from './identities';

const rotation = async (signer, fromKey, toKey, ts, seed = signer.seed) => {
    const [oldKid, newKid] = [encryptionKeyId(fromKey), encryptionKeyId(toKey)];
    return {
        old_kid: oldKid, new_kid: newKid, alg: KEM_ALG, ts,
        signature: await signKeyRotation({ address: signer.address, oldKid, newKid, ts }, seed),
    };
};

describe('a contact whose key was replaced by a signed rotation', () => {
    let signer, pinned, record;
    beforeEach(async () => {
        localStorage.clear();
        signer = makeSigner('Bob');
        pinned = signer.encryptionPublicKey;
        trustContactKey(signer.address, pinned);
        record = await directoryRecord({ ...signer, encryptionPublicKey: generateEncryptionKeyPair().publicKey });
    });

    it('is named as a rotation, dated, and still blocks', async () => {
        const ts = Date.UTC(2026, 9, 14);
        const user = { ...record, encryption_key_rotations: [await rotation(signer, pinned, record.encryption_public_key, ts)] };
        render(<KeyTrustPanel user={user} />);
        expect(await screen.findByTestId('key-rotated')).toBeTruthy();
        expect(screen.getByTestId('key-changed').textContent).toContain('replaced their encryption key');
        expect(screen.getByText(/Nothing will be sent to them until you confirm/)).toBeTruthy();
        // The verdict the send path acts on is unchanged by the explanation.
        expect(checkContactKey(user.address, user.encryption_public_key)).toBe('changed');
    });

    it('follows a chain of rotations from the pinned key', async () => {
        const middle = generateEncryptionKeyPair().publicKey;
        const user = {
            ...record,
            encryption_key_rotations: [
                await rotation(signer, middle, record.encryption_public_key, 20),
                await rotation(signer, pinned, middle, 10),
            ],
        };
        render(<KeyTrustPanel user={user} />);
        expect((await screen.findByTestId('key-rotated')).textContent).toContain('2 rotations');
    });

    it('is a plain change when the rotation does not verify or does not reach', async () => {
        const stranger = makeSigner('Mallory');
        for (const rotations of [
            [await rotation(signer, pinned, record.encryption_public_key, 1, stranger.seed)], // not Bob's signature
            [await rotation(signer, generateEncryptionKeyPair().publicKey, record.encryption_public_key, 1)], // from another key
            [],
        ]) {
            const { unmount } = render(<KeyTrustPanel user={{ ...record, encryption_key_rotations: rotations }} />);
            await waitFor(() => expect(screen.getByTestId('key-changed').textContent).toContain('encryption key changed'));
            await new Promise((r) => setTimeout(r, 50));
            expect(screen.queryByTestId('key-rotated')).toBeNull();
            unmount();
        }
    });
});
