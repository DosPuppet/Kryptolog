// Replacing the active identity's encryption key from a connected page
// (crypto-core 5.1.0): the window approves it, the vault holds the new key
// before the page gets anything to publish, and undoing is narrowed to the
// rotation just made — and destroys nothing even then.

import { describe, it, expect, vi } from 'vitest';
import { bootWithVault, restart, VAULT_PASSWORD } from './harness.js';
import { pageSender, internalSender } from './chrome-mock.js';
import {
    verifyEncryptionKeyAttestation, verifyKeyRotation, KEM_ALG, encryptMessage, decryptMessage, encryptionSeedFor,
} from '../src/utils/crypto.js';

const SITE = 'https://app.example';
const account = (h) => h.state.vault.accounts[0];

const rotate = async (h, request = { type: 'ROTATE_ENCRYPTION_KEY', ts: Date.now() }, origin = SITE) => {
    const pending = h.send(request, pageSender(origin));
    let id = null;
    for (let i = 0; i < 200 && !id; i++) {
        await new Promise((r) => setTimeout(r, 5));
        id = h.approvals.nextApprovalId();
    }
    const shown = id ? h.approvals.peekApproval(id) : null;
    if (shown) h.approvals.settleApproval(id, true);
    return { res: await pending, shown };
};

describe('ROTATE_ENCRYPTION_KEY', () => {
    it('asks in words, saves the rotation, and returns what the page publishes, signed', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const before = account(h);
        const sealedBefore = await encryptMessage('older history', before.encryption.publicKey);
        const ts = Date.now();
        const { res, shown } = await rotate(h, { type: 'ROTATE_ENCRYPTION_KEY', ts });

        expect(shown.data).toMatchObject({ kind: 'key-rotation', origin: SITE, details: { address: before.id } });
        expect(res.success).toBe(true);
        const after = account(h);
        expect(res.result).toMatchObject({
            encryptionPublicKey: after.encryption.publicKey,
            oldKid: before.encryption.kid,
            newKid: after.encryption.kid,
        });
        expect(after.retiredEncryption.map((k) => k.kid)).toEqual([before.encryption.kid]);
        // Saved before the answer: a restarted worker, unlocked from disk,
        // holds the rotated account — the new key and the retired one.
        const r = await restart(h);
        await r.send({ type: 'UNLOCK', password: VAULT_PASSWORD }, internalSender());
        expect(account(r).encryption.kid).toBe(res.result.newKid);
        expect(account(r).retiredEncryption.map((k) => k.kid)).toEqual([before.encryption.kid]);
        expect(await verifyEncryptionKeyAttestation({
            address: before.id, identityPublicKey: before.identity.publicKey,
            encryptionPublicKey: res.result.encryptionPublicKey, attestation: res.result.attestation,
        })).toBe(true);
        expect(await verifyKeyRotation({
            address: before.id, identityPublicKey: before.identity.publicKey,
            rotation: { old_kid: res.result.oldKid, new_kid: res.result.newKid, alg: KEM_ALG, ts, signature: res.result.signature },
        })).toBe(true);
        // Older history still opens, with the retired key its kid names.
        expect(await decryptMessage(sealedBefore, encryptionSeedFor(after, sealedBefore))).toBe('older history');
    });

    it('changes nothing when the window is refused', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const before = account(h).encryption.kid;
        const pending = h.send({ type: 'ROTATE_ENCRYPTION_KEY', ts: Date.now() }, pageSender(SITE));
        let id = null;
        for (let i = 0; i < 200 && !id; i++) { await new Promise((r) => setTimeout(r, 5)); id = h.approvals.nextApprovalId(); }
        h.approvals.settleApproval(id, false);
        expect((await pending).success).toBe(false);
        expect(account(h).encryption.kid).toBe(before);
    });

    it('refuses a site that is not connected, and a clock far from ours', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        expect((await h.send({ type: 'ROTATE_ENCRYPTION_KEY', ts: Date.now() }, pageSender('https://other.example'))).success).toBe(false);
        expect((await h.send({ type: 'ROTATE_ENCRYPTION_KEY', ts: Date.now() - 3_600_000 }, pageSender(SITE))).success).toBe(false);
        expect(h.approvals.nextApprovalId()).toBeNull();
    });
});

describe('REVERT_ENCRYPTION_KEY_ROTATION', () => {
    it('undoes the rotation just made, for the page that asked, keeping the refused key retired', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const before = account(h).encryption.kid;
        const { res } = await rotate(h);
        const undo = await h.send({ type: 'REVERT_ENCRYPTION_KEY_ROTATION', newKid: res.result.newKid }, pageSender(SITE));
        expect(undo.success).toBe(true);
        expect(account(h).encryption.kid).toBe(before);
        expect(account(h).retiredEncryption.map((k) => k.kid)).toEqual([res.result.newKid]);
        // Once only.
        const again = await h.send({ type: 'REVERT_ENCRYPTION_KEY_ROTATION', newKid: res.result.newKid }, pageSender(SITE));
        expect(again.success).toBe(false);
    });

    it('refuses another site, another key, and a stale request', async () => {
        const h = await bootWithVault({ connect: [SITE, 'https://other.example'] });
        const { res } = await rotate(h);
        const current = account(h).encryption.kid;
        for (const [request, origin] of [
            [{ type: 'REVERT_ENCRYPTION_KEY_ROTATION', newKid: res.result.newKid }, 'https://other.example'],
            [{ type: 'REVERT_ENCRYPTION_KEY_ROTATION', newKid: res.result.oldKid }, SITE],
        ]) {
            expect((await h.send(request, pageSender(origin))).success).toBe(false);
        }
        vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 6 * 60 * 1000);
        expect((await h.send({ type: 'REVERT_ENCRYPTION_KEY_ROTATION', newKid: res.result.newKid }, pageSender(SITE))).success).toBe(false);
        vi.restoreAllMocks();
        expect(account(h).encryption.kid).toBe(current);
    });

    it('a refused undo leaves the real one available', async () => {
        // crypto-core would refuse the wrong kid anyway; the handler's own check
        // is what keeps that refusal from spending the pending undo with it.
        const h = await bootWithVault({ connect: [SITE] });
        const before = account(h).encryption.kid;
        const { res } = await rotate(h);
        const wrong = await h.send({ type: 'REVERT_ENCRYPTION_KEY_ROTATION', newKid: res.result.oldKid }, pageSender(SITE));
        expect(wrong.success).toBe(false);
        const right = await h.send({ type: 'REVERT_ENCRYPTION_KEY_ROTATION', newKid: res.result.newKid }, pageSender(SITE));
        expect(right.success).toBe(true);
        expect(account(h).encryption.kid).toBe(before);
    });
});

describe('DESTROY_RETIRED_ENCRYPTION_KEY', () => {
    it('destroys a retired key from the extension, and never the current one', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { res } = await rotate(h);
        expect((await h.send({ type: 'DESTROY_RETIRED_ENCRYPTION_KEY', kid: res.result.newKid }, internalSender())).success).toBe(false);
        expect((await h.send({ type: 'DESTROY_RETIRED_ENCRYPTION_KEY', kid: res.result.oldKid }, internalSender())).success).toBe(true);
        expect(account(h).retiredEncryption).toEqual([]);
    });
});
