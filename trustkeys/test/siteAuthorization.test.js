// "Authorize" in the popup, when the popup does not live to finish it.
//
// Reported from production (2026-10-15): clicking Authorize on a site's first
// visit left it untrusted. chrome.permissions.request opens Chrome's dialog,
// the popup closes, and the popup code that was to tell the worker went with
// it — the host permission granted, the vault never told. The worker now
// completes the authorization itself when Chrome reports the grant, for the
// one site the popup announced and nothing else.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { bootWithVault, restart } from './harness.js';
import { internalSender } from './chrome-mock.js';

const SITE = 'https://app.example'; // the mock's active tab
const GRANT = { origins: [`${SITE}/*`] };

// onAdded handlers run detached from the event, through a vault save; give a
// refusal long enough that a bug would have shown.
const settle = () => new Promise((r) => setTimeout(r, 100));

const trusted = async (h) => {
    const res = await h.send({ type: 'GET_TRUSTED_SITES' }, internalSender());
    return res.sites.map((s) => s.origin).includes(SITE);
};

afterEach(() => vi.useRealTimers());

describe('a popup that closes under Chrome\'s permission dialog', () => {
    it('still gets its site trusted once Chrome reports the grant', async () => {
        const h = await bootWithVault();
        expect(await h.send({ type: 'EXPECT_SITE_GRANT' }, internalSender()))
            .toEqual({ success: true, origin: SITE });
        expect(await trusted(h)).toBe(false);

        h.grantPermissions(GRANT); // the popup is gone; nobody sends AUTHORIZE
        await settle();

        await vi.waitFor(() => expect(h.chrome.tabs.reload).toHaveBeenCalledTimes(1));
        expect(await trusted(h)).toBe(true);
        expect(h.chrome.scripting.registerContentScripts).toHaveBeenCalled();
    });

    it('survives the worker being stopped while the dialog is open', async () => {
        const first = await bootWithVault();
        await first.send({ type: 'EXPECT_SITE_GRANT' }, internalSender());

        const h = await restart(first);
        h.grantPermissions(GRANT);
        await vi.waitFor(() => expect(h.chrome.tabs.reload).toHaveBeenCalledTimes(1));
        expect(await trusted(h)).toBe(true);
    });
});

describe('what a grant does NOT trust', () => {
    it('a site the popup never announced (Chrome\'s own site-access menu)', async () => {
        const h = await bootWithVault();
        h.grantPermissions(GRANT);
        await settle();
        expect(await trusted(h)).toBe(false);
    });

    it('a different site than the one announced', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'EXPECT_SITE_GRANT' }, internalSender());
        h.grantPermissions({ origins: ['https://other.example/*'] });
        await settle();
        expect(await trusted(h)).toBe(false);
    });

    it('an announcement that has expired', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'EXPECT_SITE_GRANT' }, internalSender());
        const now = Date.now();
        vi.spyOn(Date, 'now').mockReturnValue(now + 3 * 60 * 1000);
        h.grantPermissions(GRANT);
        await settle();
        expect(await trusted(h)).toBe(false);
    });

    it('anything, once the popup completed it itself', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'EXPECT_SITE_GRANT' }, internalSender());
        await h.send({ type: 'AUTHORIZE_CURRENT_TAB' }, internalSender());
        await h.send({ type: 'REMOVE_TRUSTED_SITE', origin: SITE }, internalSender());

        h.grantPermissions(GRANT); // a later grant from elsewhere
        await settle();
        expect(await trusted(h)).toBe(false);
    });
});

describe('both completions for one click', () => {
    it('reload the tab once, not twice', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'EXPECT_SITE_GRANT' }, internalSender());
        h.grantPermissions(GRANT);
        await vi.waitFor(() => expect(h.chrome.tabs.reload).toHaveBeenCalledTimes(1));
        const res = await h.send({ type: 'AUTHORIZE_CURRENT_TAB' }, internalSender());

        expect(res).toMatchObject({ success: true, origin: SITE });
        await settle();
        expect(h.chrome.tabs.reload).toHaveBeenCalledTimes(1);
    });
});

describe('the announcement itself', () => {
    it('is refused for a plain-http tab', async () => {
        const h = await bootWithVault();
        h.chrome.tabs.query.mockResolvedValue([{ id: 1, url: 'http://insecure.example/' }]);
        const res = await h.send({ type: 'EXPECT_SITE_GRANT' }, internalSender());
        expect(res).toMatchObject({ success: false, error: expect.stringMatching(/HTTPS/) });
    });
});
