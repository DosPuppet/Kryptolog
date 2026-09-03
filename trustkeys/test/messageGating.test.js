// Internal-only message types must refuse a content script (audit M-5).
//
// GET_PENDING_REQUEST and RESOLVE_REQUEST shipped with NO sender check at all —
// the only two handlers that approve a signature or a decryption. The other
// twelve had `sender.id !== chrome.runtime.id`, which a content script passes
// because it runs under the extension's id too. Both are asserted here by
// enumeration, so a NEW internal handler that ships with the weak check (or
// none) fails this test rather than shipping.

import { describe, it, expect } from 'vitest';
import { boot, bootWithVault } from './harness.js';
import { internalSender, pageSender, foreignSender } from './chrome-mock.js';

// Every type that must be reachable ONLY from the extension's own pages.
const INTERNAL_ONLY = [
    { type: 'GET_PENDING_REQUEST', requestId: 'x' },
    { type: 'RESOLVE_REQUEST', requestId: 'x', approved: true },
    { type: 'GET_TRUSTED_SITES' },
    { type: 'ADD_TRUSTED_SITE', origin: 'https://evil.example' },
    { type: 'REMOVE_TRUSTED_SITE', origin: 'https://app.example' },
    { type: 'SET_SITE_AUTOSIGN', origin: 'https://app.example', enabled: true },
    { type: 'AUTHORIZE_CURRENT_TAB' },
    { type: 'CREATE_ACCOUNT', name: 'evil' },
    { type: 'GET_ACCOUNTS' },
    { type: 'SET_ACTIVE_ACCOUNT', id: 'x' },
    { type: 'DELETE_ACCOUNT', id: 'x' },
    { type: 'EXPORT_KEYS', password: 'guess' },
    { type: 'EXPORT_KEYS_ENCRYPTED', password: 'guess', passphrase: 'p' },
    { type: 'IMPORT_KEYS', accounts: [] },
];

describe('internal-only handlers reject external senders', () => {
    // boot() rather than bootWithVault(): the guard is the first statement in
    // every one of these handlers, so it must refuse before any vault exists —
    // and skipping setup keeps 28 parametrised cases off the 600k-iteration KDF.
    it.each(INTERNAL_ONLY.map(r => [r.type, r]))('%s refuses a content script', async (_type, request) => {
        const h = await boot();
        const res = await h.send(request, pageSender('https://app.example'));
        expect(res.success).toBe(false);
        expect(res.error).toMatch(/unauthorized/i);
    });

    it.each(INTERNAL_ONLY.map(r => [r.type, r]))('%s refuses another extension', async (_type, request) => {
        const h = await boot();
        const res = await h.send(request, foreignSender());
        expect(res.success).toBe(false);
        expect(res.error).toMatch(/unauthorized/i);
    });
});

describe('the approval channel specifically (M-5)', () => {
    it('a content script cannot read a pending request', async () => {
        const h = await bootWithVault({ connect: ['https://app.example'] });

        // A real approval, registered by the connected site.
        const signing = h.send(
            { type: 'SIGN', message: 'please sign' }, pageSender('https://app.example')
        );
        await new Promise(r => setTimeout(r, 0));
        const id = h.approvals.nextApprovalId();
        expect(id).toBeTruthy();

        const peeked = await h.send({ type: 'GET_PENDING_REQUEST', requestId: id }, pageSender());
        expect(peeked.success).toBe(false);

        // ...and cannot approve it either. That is the one that matters: it
        // would have produced a signature with no user involvement at all.
        const resolved = await h.send(
            { type: 'RESOLVE_REQUEST', requestId: id, approved: true }, pageSender()
        );
        expect(resolved.success).toBe(false);

        // The request is still pending — nothing was signed.
        expect(h.state.pendingRequests.has(id)).toBe(true);
        h.approvals.rejectAllApprovals('test cleanup');
        await expect(signing).resolves.toMatchObject({ success: false });
    });

    it('the popup can read and approve it', async () => {
        const h = await bootWithVault({ connect: ['https://app.example'] });
        const signing = h.send(
            { type: 'SIGN', message: 'please sign' }, pageSender('https://app.example')
        );
        await new Promise(r => setTimeout(r, 0));
        const id = h.approvals.nextApprovalId();

        const peeked = await h.send({ type: 'GET_PENDING_REQUEST', requestId: id }, internalSender());
        expect(peeked.success).toBe(true);
        expect(peeked.request.type).toBe('SIGN');
        expect(peeked.request.data.message).toBe('please sign');

        await h.send({ type: 'RESOLVE_REQUEST', requestId: id, approved: true }, internalSender());
        await expect(signing).resolves.toMatchObject({ success: true });
    });
});

describe('unknown message types', () => {
    it('always get a response (audit M-6)', async () => {
        // An unhandled type used to fall out of the switch without calling
        // sendResponse, leaving the caller's promise pending until teardown.
        const h = await boot();
        const res = await h.send({ type: 'NOT_A_REAL_TYPE' }, internalSender());
        expect(res).toMatchObject({ success: false });
        expect(res.error).toMatch(/unknown message type/i);
    });
});
