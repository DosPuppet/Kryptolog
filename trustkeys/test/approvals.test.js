// Bounds on the pending-approval map (audit M-6).
//
// Every external SIGN/DECRYPT/UNWRAP added a Map entry and opened an OS window,
// with no cap, no dedup, no timeout and no cleanup. A looping site opened a
// window per call; closing a window without clicking left the page's promise
// pending forever AND the entry in the Map permanently.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { bootWithVault, VAULT_PASSWORD } from './harness.js';
import { pageSender, internalSender } from './chrome-mock.js';

const SITE = 'https://app.example';
const OTHER = 'https://other.example';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const settle = () => new Promise(r => setTimeout(r, 0));

/**
 * Fire a SIGN from `origin`; resolves once the request is REGISTERED, not once
 * it is answered. The answer is returned wrapped: an async function flattens a
 * returned promise, so handing it back bare would make `await askToSign(...)`
 * block on the approval the test has not given yet.
 */
const askToSign = async (h, origin = SITE, message = 'sign me') => {
    const answer = h.send({ type: 'SIGN', message }, pageSender(origin));
    await settle();
    return { answer };
};

afterEach(() => vi.useRealTimers());

describe('request ids', () => {
    it('are crypto.randomUUID, not Math.random (audit M-5)', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: p } = await askToSign(h);
        expect(h.approvals.nextApprovalId()).toMatch(UUID_RE);
        h.approvals.rejectAllApprovals('test');
        await p;
    });
});

describe('one window, not one per call', () => {
    it('focuses the open approval window instead of stacking another', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: a } = await askToSign(h, SITE, 'first');
        const { answer: b } = await askToSign(h, SITE, 'second');

        expect(h.chrome.windows.create).toHaveBeenCalledTimes(1);
        expect(h.chrome.windows.update).toHaveBeenCalledTimes(1);
        expect(h.state.pendingRequests.size).toBe(2);

        h.approvals.rejectAllApprovals('test');
        await Promise.all([a, b]);
    });

    it('does not mistake the unlock nudge for the approval window', async () => {
        // A site that calls CONNECT while locked gets a "please unlock" window,
        // and that window stays open showing the dashboard once the user
        // unlocks. If it shared a tracking slot with the approval window, the
        // next signature request would focus it — showing the dashboard, not
        // the request — and then time out unanswered.
        const h = await bootWithVault({ connect: [SITE] });
        await h.send({ type: 'LOCK' }, internalSender());
        await h.send({ type: 'CONNECT' }, pageSender(OTHER));
        expect(h.chrome.windows.create).toHaveBeenCalledTimes(1); // the nudge
        const nudge = h.lastWindowId();

        await h.send({ type: 'UNLOCK', password: VAULT_PASSWORD }, internalSender());
        const { answer } = await askToSign(h);

        // A separate window, and the nudge is untouched.
        expect(h.chrome.windows.create).toHaveBeenCalledTimes(2);
        expect(h.lastWindowId()).not.toBe(nudge);
        expect(h.state.approvalWindowId).toBe(h.lastWindowId());
        expect(h.state.popupWindowId).toBe(nudge);

        // ...and closing the nudge does not cancel the pending approval.
        h.closeWindow(nudge);
        expect(h.state.pendingRequests.size).toBe(1);

        h.approvals.rejectAllApprovals('test');
        await answer;
    });

    it('opens a fresh window once the previous one is gone', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: a } = await askToSign(h);
        h.closeWindow(h.lastWindowId());
        await expect(a).resolves.toMatchObject({ success: false });

        const { answer: b } = await askToSign(h);
        expect(h.chrome.windows.create).toHaveBeenCalledTimes(2);
        h.approvals.rejectAllApprovals('test');
        await b;
    });
});

describe('caps', () => {
    it('refuses a site more than MAX_PENDING_PER_ORIGIN pending approvals', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const cap = h.approvals.MAX_PENDING_PER_ORIGIN;

        const accepted = [];
        for (let i = 0; i < cap; i++) accepted.push((await askToSign(h, SITE, `m${i}`)).answer);
        expect(h.state.pendingRequests.size).toBe(cap);

        // The one over the line is refused immediately rather than queued.
        const refused = await h.send({ type: 'SIGN', message: 'too many' }, pageSender(SITE));
        expect(refused.success).toBe(false);
        expect(refused.error).toMatch(/too many pending approvals/i);
        expect(h.state.pendingRequests.size).toBe(cap);

        h.approvals.rejectAllApprovals('test');
        await Promise.all(accepted);
    });

    it('the cap is per origin — one site cannot lock out another', async () => {
        const h = await bootWithVault({ connect: [SITE, OTHER] });
        const cap = h.approvals.MAX_PENDING_PER_ORIGIN;

        const flood = [];
        for (let i = 0; i < cap; i++) flood.push((await askToSign(h, SITE, `m${i}`)).answer);

        const { answer: other } = await askToSign(h, OTHER, 'legitimate');
        expect(h.state.pendingRequests.size).toBe(cap + 1);

        h.approvals.rejectAllApprovals('test');
        await Promise.all([...flood, other]);
    });
});

describe('dismissing the window settles the requests', () => {
    it('closing without clicking rejects the page promise instead of hanging it', async () => {
        // The audit's exact scenario. Previously this promise never settled and
        // its Map entry was never removed.
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: pending } = await askToSign(h);

        h.closeWindow(h.lastWindowId());

        await expect(pending).resolves.toMatchObject({ success: false });
        expect(h.state.pendingRequests.size).toBe(0);
    });

    it('rejects every queued request, not just the visible one', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: a } = await askToSign(h, SITE, 'first');
        const { answer: b } = await askToSign(h, SITE, 'second');

        h.closeWindow(h.lastWindowId());

        await expect(a).resolves.toMatchObject({ success: false });
        await expect(b).resolves.toMatchObject({ success: false });
        expect(h.state.pendingRequests.size).toBe(0);
    });

    it('ignores an unrelated window closing', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: pending } = await askToSign(h);
        h.closeWindow(9999);
        expect(h.state.pendingRequests.size).toBe(1);
        h.approvals.rejectAllApprovals('test');
        await pending;
    });
});

describe('timeout', () => {
    it('an unanswered request settles instead of living forever', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        vi.useFakeTimers();

        const pending = h.send({ type: 'SIGN', message: 'ignored' }, pageSender(SITE));
        await vi.advanceTimersByTimeAsync(0);
        expect(h.state.pendingRequests.size).toBe(1);

        await vi.advanceTimersByTimeAsync(h.approvals.APPROVAL_TIMEOUT_MS + 1000);

        await expect(pending).resolves.toMatchObject({ success: false });
        expect((await pending).error).toMatch(/timed out/i);
        expect(h.state.pendingRequests.size).toBe(0);
    });

    it('an approved request does not later fire its timeout', async () => {
        // Settling exactly once is what stops a second sendResponse on a dead
        // channel, and what keeps the Map accurate.
        const h = await bootWithVault({ connect: [SITE] });
        vi.useFakeTimers();

        const pending = h.send({ type: 'SIGN', message: 'ok' }, pageSender(SITE));
        await vi.advanceTimersByTimeAsync(0);
        const id = h.approvals.nextApprovalId();

        const resolved = h.send({ type: 'RESOLVE_REQUEST', requestId: id, approved: true }, internalSender());
        await vi.advanceTimersByTimeAsync(0);
        await expect(resolved).resolves.toMatchObject({ success: true });
        await expect(pending).resolves.toMatchObject({ success: true });

        await vi.advanceTimersByTimeAsync(h.approvals.APPROVAL_TIMEOUT_MS + 1000);
        expect(h.state.pendingRequests.size).toBe(0);
        // Still the approved answer — the timeout did not overwrite it.
        await expect(pending).resolves.toMatchObject({ success: true });
    });
});

describe('the popup walks the queue', () => {
    it('RESOLVE_REQUEST hands back the next pending id', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: a } = await askToSign(h, SITE, 'first');
        const { answer: b } = await askToSign(h, SITE, 'second');

        const firstId = h.approvals.nextApprovalId();
        const res = await h.send(
            { type: 'RESOLVE_REQUEST', requestId: firstId, approved: true }, internalSender()
        );
        expect(res.success).toBe(true);
        expect(res.next).toBeTruthy();
        expect(res.next).not.toBe(firstId);

        // ...and the popup can fetch it without knowing its id.
        const peeked = await h.send({ type: 'GET_PENDING_REQUEST' }, internalSender());
        expect(peeked.success).toBe(true);
        expect(peeked.request.data.message).toBe('second');

        await expect(a).resolves.toMatchObject({ success: true });
        h.approvals.rejectAllApprovals('test');
        await b;
    });

    it('reports no next request when the queue empties', async () => {
        const h = await bootWithVault({ connect: [SITE] });
        const { answer: only } = await askToSign(h);
        const id = h.approvals.nextApprovalId();

        const res = await h.send({ type: 'RESOLVE_REQUEST', requestId: id, approved: false }, internalSender());
        expect(res.next).toBeNull();
        await expect(only).resolves.toMatchObject({ success: false });
    });
});
