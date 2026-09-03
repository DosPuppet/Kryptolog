// Idle auto-lock and session persistence (audit M-4).
//
// Three defects compounded, and the tests are grouped by which one they pin:
//   1. the vault PASSWORD was persisted in chrome.storage.session;
//   2. the idle check ran only at service-worker startup, so a long-lived
//      worker never locked;
//   3. updateActivity() ran for EVERY message, so a connected page could hold
//      the vault open forever by polling.

import { describe, it, expect } from 'vitest';
import { boot, bootWithVault, restart, VAULT_PASSWORD } from './harness.js';
import { internalSender, pageSender } from './chrome-mock.js';

const sessionObj = (h) => Object.fromEntries(h.sessionStore);

describe('what the session stores (1: not the password)', () => {
    it('never writes the vault password anywhere in session storage', async () => {
        const h = await bootWithVault();
        const dump = JSON.stringify(sessionObj(h));
        expect(dump).not.toContain(VAULT_PASSWORD);
        expect(sessionObj(h).sessionPassword).toBeUndefined();
    });

    it('stores the derived key and salt as hex, so a worker restart can use them', async () => {
        const h = await bootWithVault();
        const s = sessionObj(h);
        expect(s.vaultKeyHex).toMatch(/^[0-9a-f]{64}$/);   // 32 bytes
        expect(s.vaultSaltHex).toMatch(/^[0-9a-f]{32}$/);  // 16 bytes
        expect(typeof s.lastActive).toBe('number');
    });

    it('the local vault blob holds no plaintext key material either', async () => {
        const h = await bootWithVault();
        const dump = JSON.stringify(Object.fromEntries(h.localStore));
        expect(dump).not.toContain(VAULT_PASSWORD);
        expect(dump).not.toContain('privateKey');
    });

    it('locking clears the session and the in-memory key', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'LOCK' }, internalSender());

        expect(sessionObj(h).vaultKeyHex).toBeUndefined();
        expect(h.state.vaultKey).toBeNull();
        expect(h.state.vaultKeyBytes).toBeNull();
        expect(h.state.isLocked).toBe(true);
    });
});

describe('resuming after a service-worker restart', () => {
    it('reopens the vault from the cached key, with no password anywhere', async () => {
        const h = await bootWithVault();
        const before = h.state.vault.accounts[0].id;

        const h2 = await restart(h);
        expect(h2.state.isLocked).toBe(false);
        expect(h2.state.vault.accounts[0].id).toBe(before);
    });

    it('refuses to resume a session that has gone idle, and wipes it', async () => {
        const h = await bootWithVault();
        // Backdate past the idle window.
        const stale = Object.fromEntries(h.sessionStore);
        stale.lastActive = Date.now() - (h.session.IDLE_TIMEOUT_MS + 1000);
        h.sessionStore.set('lastActive', stale.lastActive);

        const h2 = await restart(h);
        expect(h2.state.isLocked).toBe(true);
        expect(Object.fromEntries(h2.sessionStore).vaultKeyHex).toBeUndefined();
    });

    it('stays locked when the cached key no longer opens the stored vault', async () => {
        const h = await bootWithVault();
        h.sessionStore.set('vaultKeyHex', '00'.repeat(32));

        const h2 = await restart(h);
        expect(h2.state.isLocked).toBe(true);
        // Stale material is dropped rather than left lying around.
        expect(Object.fromEntries(h2.sessionStore).vaultKeyHex).toBeUndefined();
    });
});

describe('the idle alarm actually fires (2)', () => {
    it('registers a periodic alarm at load', async () => {
        const h = await boot();
        expect(h.chrome.alarms.create).toHaveBeenCalledWith(
            h.session.IDLE_ALARM, { periodInMinutes: h.session.IDLE_CHECK_MINUTES }
        );
    });

    it('leaves an active session alone', async () => {
        const h = await bootWithVault();
        h.fireAlarm(h.session.IDLE_ALARM);
        await new Promise(r => setTimeout(r, 0));
        expect(h.state.isLocked).toBe(false);
    });

    it('locks an idle session WITHOUT needing a worker restart', async () => {
        // This is the whole defect: the old check lived in initializeStorage, so
        // while the worker stayed alive nothing ever re-checked.
        const h = await bootWithVault();
        h.sessionStore.set('lastActive', Date.now() - (h.session.IDLE_TIMEOUT_MS + 1000));

        h.fireAlarm(h.session.IDLE_ALARM);
        await new Promise(r => setTimeout(r, 0));

        expect(h.state.isLocked).toBe(true);
        expect(Object.fromEntries(h.sessionStore).vaultKeyHex).toBeUndefined();
    });

    it('ignores alarms that are not ours', async () => {
        const h = await bootWithVault();
        h.sessionStore.set('lastActive', Date.now() - (h.session.IDLE_TIMEOUT_MS + 1000));
        h.fireAlarm('some-other-alarm');
        await new Promise(r => setTimeout(r, 0));
        expect(h.state.isLocked).toBe(false);
    });
});

describe('what counts as activity (3)', () => {
    const readLastActive = (h) => Object.fromEntries(h.sessionStore).lastActive;

    it('a page-originated message does NOT extend the session', async () => {
        // The audit's scenario: a connected site polling GET_STATUS every 50
        // minutes held the vault open indefinitely, with no user present.
        const h = await bootWithVault({ connect: ['https://app.example'] });
        const backdated = Date.now() - (h.session.IDLE_TIMEOUT_MS - 1000);
        h.sessionStore.set('lastActive', backdated);

        await h.send({ type: 'GET_STATUS' }, pageSender('https://app.example'));
        expect(readLastActive(h)).toBe(backdated);

        // ...so the alarm still locks it when the window elapses.
        h.sessionStore.set('lastActive', Date.now() - (h.session.IDLE_TIMEOUT_MS + 1));
        await h.send({ type: 'GET_STATUS' }, pageSender('https://app.example'));
        h.fireAlarm(h.session.IDLE_ALARM);
        await new Promise(r => setTimeout(r, 0));
        expect(h.state.isLocked).toBe(true);
    });

    it('a message from the extension\'s own UI DOES extend it', async () => {
        const h = await bootWithVault();
        const backdated = Date.now() - 60_000;
        h.sessionStore.set('lastActive', backdated);

        await h.send({ type: 'GET_STATUS' }, internalSender());
        expect(readLastActive(h)).toBeGreaterThan(backdated);
    });

    it('does not resurrect a locked session', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'LOCK' }, internalSender());
        await h.send({ type: 'GET_STATUS' }, internalSender());
        expect(readLastActive(h)).toBeUndefined();
    });
});
