// What a connected page may get signed (crypto-core 3.0.0, audit 2026-10-12 K-03).
//
// sign() used to sign any string a connected site sent, so a site could hand
// over a Kryptolog LOGIN challenge for another server, a key attestation or an
// account deletion, and the approval window showed a raw body nobody reads.
// The reserved bodies are now built inside the extension from typed fields,
// with the origin Chrome attaches to the sender, and the window shows a `kind`.

import { describe, it, expect } from 'vitest';
import { bootWithVault } from './harness.js';
import { pageSender } from './chrome-mock.js';
import {
    domainSeparate, SIGNING_CONTEXT, loginChallengeBody, accountDeletionBody,
    multisigApprovalMessage, verifySignature,
} from '../src/utils/crypto.js';

const SITE = 'https://app.example';

/** Send from the connected site, approve the window, return the response. */
const approve = async (h, request, origin = SITE) => {
    const pending = h.send(request, pageSender(origin));
    // Some handlers hash before they open the window, so poll, bounded.
    let id = null;
    for (let i = 0; i < 200 && !id; i++) {
        await new Promise((r) => setTimeout(r, 5));
        id = h.approvals.nextApprovalId();
    }
    const shown = h.approvals.peekApproval(id);
    if (shown) h.approvals.settleApproval(id, true);
    return { res: await pending, shown };
};

const account = (h) => h.state.vault.accounts[0];

describe('sign() refuses the reserved contexts', () => {
    it.each([
        SIGNING_CONTEXT.LOGIN, SIGNING_CONTEXT.KEY_ATTESTATION, SIGNING_CONTEXT.ACCOUNT_DELETION,
        SIGNING_CONTEXT.MULTISIG_APPROVAL, SIGNING_CONTEXT.MESSAGE, 'some-future-context',
    ])('a %s body', async (context) => {
        const h = await bootWithVault({ connect: [SITE] });
        const res = await h.send(
            { type: 'SIGN', message: domainSeparate(context, 'anything') }, pageSender(SITE)
        );
        expect(res.success).toBe(false);
        expect(res.error).toMatch(/dedicated API/);
        expect(h.approvals.nextApprovalId()).toBeNull(); // no window was even opened
    });

    it('still signs a document (`content`), and shows its text rather than the header', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { res, shown } = await approve(h, {
            type: 'SIGN', message: domainSeparate(SIGNING_CONTEXT.CONTENT, 'I agree to the terms'),
        });
        expect(res.success).toBe(true);
        expect(shown.data).toMatchObject({ kind: 'content', details: { text: 'I agree to the terms' } });
    });
});

describe('signLogin', () => {
    it('builds the body with the origin the BROWSER reports, and the account\'s own key', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { res, shown } = await approve(h, { type: 'SIGN_LOGIN', nonce: 'ab12', deployment: 'dep-1' });

        expect(res.success).toBe(true);
        expect(shown.data).toMatchObject({ kind: 'login', origin: SITE, details: { deployment: 'dep-1' } });
        const expected = loginChallengeBody({
            nonce: 'ab12', origin: SITE, deployment: 'dep-1', encryptionKey: account(h).mlkem.publicKey,
        });
        expect(await verifySignature(expected, res.signature, account(h).mldsa.publicKey)).toBe(true);
    });

    it('ignores an origin the page names: it can only ever sign in to itself', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { res } = await approve(h, {
            type: 'SIGN_LOGIN', nonce: 'ab12', deployment: 'dep-1', origin: 'https://bank.example',
        });
        const forOther = loginChallengeBody({
            nonce: 'ab12', origin: 'https://bank.example', deployment: 'dep-1',
            encryptionKey: account(h).mlkem.publicKey,
        });
        expect(await verifySignature(forOther, res.signature, account(h).mldsa.publicKey)).toBe(false);
    });

    it('refuses a site that is not connected', async () => {
        const h = await bootWithVault();
        const res = await h.send({ type: 'SIGN_LOGIN', nonce: 'ab12', deployment: 'dep-1' }, pageSender(SITE));
        expect(res.success).toBe(false);
    });

    it('refuses malformed fields instead of signing something nobody built', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const res = await h.send(
            { type: 'SIGN_LOGIN', nonce: 'zz\nnonce=00', deployment: 'dep-1' }, pageSender(SITE)
        );
        expect(res.success).toBe(false);
    });
});

describe('signAccountDeletion', () => {
    it('describes the mode and the redaction count, bound to the asking site', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const fields = { nonce: 'ab12', mode: 'erase', redactionKeys: ['dm:2', 'group:10'], deployment: 'dep-1' };
        const { res, shown } = await approve(h, { type: 'SIGN_ACCOUNT_DELETION', ...fields });

        expect(shown.data).toMatchObject({
            kind: 'account-deletion', details: { mode: 'erase', redactions: 2 },
        });
        const body = await accountDeletionBody({ ...fields, origin: SITE });
        expect(await verifySignature(body, res.signature, account(h).mldsa.publicKey)).toBe(true);
    });

    it('refuses a redaction list that is not one', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const res = await h.send({
            type: 'SIGN_ACCOUNT_DELETION', nonce: 'ab12', mode: 'erase',
            redactionKeys: ['dm:1', 'drop table'], deployment: 'dep-1',
        }, pageSender(SITE));
        expect(res.success).toBe(false);
    });
});

describe('signMultisigApproval', () => {
    it('names the workflow and signs the approval body', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const fields = { workflowId: 7, secretId: 42, ciphertextSha256: 'ab'.repeat(32) };
        const { res, shown } = await approve(h, { type: 'SIGN_MULTISIG_APPROVAL', ...fields });

        expect(shown.data).toMatchObject({ kind: 'multisig-approval', details: { workflowId: 7 } });
        const body = multisigApprovalMessage(7, 42, 'ab'.repeat(32));
        expect(await verifySignature(body, res.signature, account(h).mldsa.publicKey)).toBe(true);
    });
});

describe('signMessage without a silent-signing grant', () => {
    it('asks, as a chat message, rather than being refused by the context rule', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const body = domainSeparate(SIGNING_CONTEXT.MESSAGE, 'from=aa\nconv=bb');
        const { res, shown } = await approve(h, { type: 'SIGN_MESSAGE', message: body });
        expect(res.success).toBe(true);
        expect(shown.data.kind).toBe('message');
    });
});
