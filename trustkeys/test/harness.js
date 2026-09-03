// Boots the background service worker against a fresh chrome mock.
//
// The worker registers its listeners and kicks off initializeStorage() at import
// time, so the mock has to exist BEFORE the import and the module graph has to
// be reset between tests — otherwise state (the vault, the pending-request map)
// leaks from one test into the next.

import { vi } from 'vitest';
import { installChrome, internalSender, pageSender } from './chrome-mock.js';

export const VAULT_PASSWORD = 'correct horse battery staple';

export const boot = async (seed) => {
    vi.resetModules();
    const harness = installChrome(seed);

    await import('../src/background/index.js');
    const { state } = await import('../src/background/state.js');
    const approvals = await import('../src/background/approvals.js');
    const session = await import('../src/background/session.js');

    const booted = { ...harness, state, approvals, session };

    // The worker kicks off initializeStorage() at import but does not await it;
    // every message handler awaits that promise first. Sending one flushes it,
    // so tests observe a fully-initialized worker (session restore included).
    // Deliberately a PAGE sender: an internal one would count as user activity
    // and reset lastActive, which several tests are asserting on.
    await booted.send({ type: 'GET_STATUS' }, pageSender());
    return booted;
};

/** Boot with a vault that is set up, unlocked, and holds one account. */
export const bootWithVault = async ({ connect = [] } = {}) => {
    const h = await boot();
    await h.send({ type: 'SETUP_PASSWORD', password: VAULT_PASSWORD }, internalSender());
    await h.send({ type: 'CREATE_ACCOUNT', name: 'Test' }, internalSender());
    // Go through the real handler rather than poking state.vault.permissions:
    // that writes the grant to disk, so a connected site survives a lock/unlock
    // the way it does in production.
    for (const origin of connect) {
        await h.send({ type: 'ADD_TRUSTED_SITE', origin }, internalSender());
    }
    return h;
};

/**
 * Simulate an MV3 service-worker restart: the module graph and all in-memory
 * state are discarded, chrome.storage survives. This is the path that used to
 * resume from a stored PASSWORD (audit M-4).
 */
export const restart = (h) => boot({
    local: Object.fromEntries(h.localStore),
    session: Object.fromEntries(h.sessionStore),
});
