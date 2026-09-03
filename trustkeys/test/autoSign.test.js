// The silent message-signing guard (audit S1 + per-site grant).
//
// SIGN_MESSAGE is the one path that produces a signature with NO user prompt,
// so it is the one worth pinning: what it will sign, and for whom.

import { describe, it, expect } from 'vitest';
import { bootWithVault } from './harness.js';
import { pageSender, internalSender } from './chrome-mock.js';
import { MESSAGE_SIGNING_PREFIX, domainSeparate, SIGNING_CONTEXT } from '@kryptolog/crypto-core';

const SITE = 'https://app.example';
const chatMessage = `${MESSAGE_SIGNING_PREFIX}from=a\nconv=b\nsid=s\nct=c`;

const withAutoSign = async (origin) => {
    const h = await bootWithVault({ connect: [origin] });
    h.state.vault.autoSignSites[origin] = true;
    return h;
};

describe('domain restriction — what it will sign', () => {
    it('signs a message-context payload for a granted site', async () => {
        const h = await withAutoSign(SITE);
        const res = await h.send({ type: 'SIGN_MESSAGE', message: chatMessage }, pageSender(SITE));
        expect(res.success).toBe(true);
        expect(typeof res.signature).toBe('string');
    });

    it('refuses a login-context payload — it cannot be used to mint a login signature', async () => {
        const h = await withAutoSign(SITE);
        const login = domainSeparate(SIGNING_CONTEXT.LOGIN, 'Sign in to Kryptolog with nonce: 1234');
        const res = await h.send({ type: 'SIGN_MESSAGE', message: login }, pageSender(SITE));
        expect(res.success).toBe(false);
        expect(res.error).toMatch(/message-context/i);
    });

    it('refuses a multisig-approval payload and arbitrary bytes', async () => {
        const h = await withAutoSign(SITE);
        const multisig = domainSeparate(SIGNING_CONTEXT.MULTISIG_APPROVAL, 'workflow=1\nsecret=2\nct=3');
        for (const message of [multisig, 'just some bytes', '', null, 42, { a: 1 }]) {
            const res = await h.send({ type: 'SIGN_MESSAGE', message }, pageSender(SITE));
            expect(res.success).toBe(false);
        }
    });

    it('refuses a payload that merely CONTAINS the prefix later on', async () => {
        const h = await withAutoSign(SITE);
        const sneaky = `${domainSeparate(SIGNING_CONTEXT.LOGIN, 'nonce')}\n${MESSAGE_SIGNING_PREFIX}`;
        const res = await h.send({ type: 'SIGN_MESSAGE', message: sneaky }, pageSender(SITE));
        expect(res.success).toBe(false);
    });
});

describe('per-site grant — for whom it will sign silently', () => {
    it('refuses a site that is not connected at all', async () => {
        const h = await bootWithVault();
        const res = await h.send({ type: 'SIGN_MESSAGE', message: chatMessage }, pageSender(SITE));
        expect(res.success).toBe(false);
        expect(res.error).toMatch(/not connected/i);
    });

    it('a connected site with NO silent-signing grant gets an approval popup, not a signature', async () => {
        // Connecting is not consent to sign as the user; that is a separate grant.
        const h = await bootWithVault({ connect: [SITE] });
        const pending = h.send({ type: 'SIGN_MESSAGE', message: chatMessage }, pageSender(SITE));
        await new Promise(r => setTimeout(r, 0));

        expect(h.chrome.windows.create).toHaveBeenCalledTimes(1);
        expect(h.approvals.nextApprovalId()).toBeTruthy();

        h.approvals.rejectAllApprovals('test');
        await expect(pending).resolves.toMatchObject({ success: false });
    });

    it('a localhost origin gets NO free pass in a production build', async () => {
        // __TRUSTKEYS_ALLOW_DEV_AUTOSIGN__ is false here (see vitest.config.js).
        // Shipped, the exemption would let any page on any localhost port sign
        // as the user with no prompt and no grant.
        const dev = 'http://localhost:5173';
        const h = await bootWithVault({ connect: [dev] });
        const pending = h.send({ type: 'SIGN_MESSAGE', message: chatMessage }, pageSender(dev));
        await new Promise(r => setTimeout(r, 0));

        expect(h.chrome.windows.create).toHaveBeenCalledTimes(1);
        h.approvals.rejectAllApprovals('test');
        await expect(pending).resolves.toMatchObject({ success: false });
    });

    it('the extension\'s own pages sign without a grant', async () => {
        const h = await bootWithVault();
        const res = await h.send({ type: 'SIGN_MESSAGE', message: chatMessage }, internalSender());
        expect(res.success).toBe(true);
    });

    it('refuses everything while locked', async () => {
        const h = await withAutoSign(SITE);
        await h.send({ type: 'LOCK' }, internalSender());
        const res = await h.send({ type: 'SIGN_MESSAGE', message: chatMessage }, pageSender(SITE));
        expect(res.success).toBe(false);
        expect(res.error).toMatch(/locked/i);
    });
});
