// Vault lifecycle: setup, unlock, export/import round-trip.
//
// This is the custodian's core storage path, and it had no test coverage at all.
// The M-4 rework changed how a save is keyed (session key instead of a retained
// password), so the round-trips need pinning against a silent regression.

import { describe, it, expect } from 'vitest';
import { boot, bootWithVault, VAULT_PASSWORD } from './harness.js';
import { internalSender } from './chrome-mock.js';

describe('setup and unlock', () => {
    it('reports no password before setup', async () => {
        const h = await boot();
        const res = await h.send({ type: 'GET_STATUS' }, internalSender());
        expect(res).toMatchObject({ hasPassword: false, isLocked: true });
    });

    it('setup leaves the vault unlocked and a blob on disk', async () => {
        const h = await boot();
        await h.send({ type: 'SETUP_PASSWORD', password: VAULT_PASSWORD }, internalSender());

        const res = await h.send({ type: 'GET_STATUS' }, internalSender());
        expect(res).toMatchObject({ hasPassword: true, isLocked: false });

        const blob = Object.fromEntries(h.localStore).vaultData;
        expect(blob).toMatchObject({
            salt: expect.stringMatching(/^[0-9a-f]+$/),
            iv: expect.stringMatching(/^[0-9a-f]+$/),
            data: expect.stringMatching(/^[0-9a-f]+$/),
        });
    });

    it('refuses a second setup over an existing vault', async () => {
        const h = await bootWithVault();
        const res = await h.send({ type: 'SETUP_PASSWORD', password: 'other' }, internalSender());
        expect(res.success).toBe(false);
    });

    it('unlocks with the right password and refuses the wrong one', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'LOCK' }, internalSender());

        expect(await h.send({ type: 'UNLOCK', password: 'wrong' }, internalSender()))
            .toMatchObject({ success: false });
        expect(h.state.isLocked).toBe(true);

        expect(await h.send({ type: 'UNLOCK', password: VAULT_PASSWORD }, internalSender()))
            .toMatchObject({ success: true });
        expect(h.state.isLocked).toBe(false);
    });
});

describe('accounts survive a save under the session key', () => {
    it('an account created after unlock is still there after a lock/unlock cycle', async () => {
        // saveVaultWithSessionKey() replaced saveVault(getSessionPassword()) at
        // this call site (audit M-4); if it wrote under the wrong key or salt,
        // the next unlock would fail rather than lose data quietly.
        const h = await bootWithVault();
        await h.send({ type: 'CREATE_ACCOUNT', name: 'Second' }, internalSender());

        await h.send({ type: 'LOCK' }, internalSender());
        await h.send({ type: 'UNLOCK', password: VAULT_PASSWORD }, internalSender());

        const { accounts } = await h.send({ type: 'GET_ACCOUNTS' }, internalSender());
        expect(accounts.map(a => a.name)).toEqual(['Test', 'Second']);
    });

    it('switching and deleting accounts also persists', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'CREATE_ACCOUNT', name: 'Second' }, internalSender());
        const before = (await h.send({ type: 'GET_ACCOUNTS' }, internalSender())).accounts;
        const second = before.find(a => a.name === 'Second');

        await h.send({ type: 'SET_ACTIVE_ACCOUNT', id: second.id }, internalSender());
        await h.send({ type: 'LOCK' }, internalSender());
        await h.send({ type: 'UNLOCK', password: VAULT_PASSWORD }, internalSender());

        let accounts = (await h.send({ type: 'GET_ACCOUNTS' }, internalSender())).accounts;
        expect(accounts.find(a => a.active).name).toBe('Second');

        await h.send({ type: 'DELETE_ACCOUNT', id: second.id }, internalSender());
        await h.send({ type: 'LOCK' }, internalSender());
        await h.send({ type: 'UNLOCK', password: VAULT_PASSWORD }, internalSender());
        accounts = (await h.send({ type: 'GET_ACCOUNTS' }, internalSender())).accounts;
        expect(accounts.map(a => a.name)).toEqual(['Test']);
    });
});

describe('export / import round-trip', () => {
    it('an encrypted .kvault export re-imports into a fresh vault', async () => {
        const source = await bootWithVault();
        const exported = await source.send(
            { type: 'EXPORT_KEYS_ENCRYPTED', password: VAULT_PASSWORD, passphrase: 'transfer-pass' },
            internalSender()
        );
        expect(exported.success).toBe(true);

        const target = await boot();
        await target.send({ type: 'SETUP_PASSWORD', password: 'target-pass' }, internalSender());
        const imported = await target.send(
            { type: 'IMPORT_KEYS', data: exported.blob, password: 'target-pass', passphrase: 'transfer-pass' },
            internalSender()
        );
        expect(imported).toMatchObject({ success: true, count: 1 });

        // The imported identity is the same key, not a new one.
        const srcAccount = source.state.vault.accounts[0];
        expect(target.state.vault.accounts[0].mldsa.publicKey).toBe(srcAccount.mldsa.publicKey);
        expect(target.state.vault.accounts[0].mlkem.publicKey).toBe(srcAccount.mlkem.publicKey);
    });

    it('the export is gated on the vault password', async () => {
        const h = await bootWithVault();
        const res = await h.send(
            { type: 'EXPORT_KEYS_ENCRYPTED', password: 'not-the-password', passphrase: 'p' },
            internalSender()
        );
        expect(res.success).toBe(false);
    });

    it('an import with the wrong transfer passphrase fails', async () => {
        const source = await bootWithVault();
        const exported = await source.send(
            { type: 'EXPORT_KEYS_ENCRYPTED', password: VAULT_PASSWORD, passphrase: 'transfer-pass' },
            internalSender()
        );

        const target = await boot();
        await target.send({ type: 'SETUP_PASSWORD', password: 'target-pass' }, internalSender());
        const res = await target.send(
            { type: 'IMPORT_KEYS', data: exported.blob, password: 'target-pass', passphrase: 'wrong' },
            internalSender()
        );
        expect(res.success).toBe(false);
    });

    it('imports under the session key when no password is supplied (audit M-4)', async () => {
        // There is no stored session password to fall back on any more, so this
        // path has to re-seal with the cached key — and the result must still
        // open under the original password.
        const source = await bootWithVault();
        const exported = await source.send(
            { type: 'EXPORT_KEYS_ENCRYPTED', password: VAULT_PASSWORD, passphrase: 'transfer-pass' },
            internalSender()
        );

        const target = await boot();
        await target.send({ type: 'SETUP_PASSWORD', password: 'target-pass' }, internalSender());
        const imported = await target.send(
            { type: 'IMPORT_KEYS', data: exported.blob, passphrase: 'transfer-pass' },
            internalSender()
        );
        expect(imported).toMatchObject({ success: true, count: 1 });

        await target.send({ type: 'LOCK' }, internalSender());
        expect(await target.send({ type: 'UNLOCK', password: 'target-pass' }, internalSender()))
            .toMatchObject({ success: true });
        expect(target.state.vault.accounts).toHaveLength(1);
    });

    it('refuses an import while locked with no password', async () => {
        const h = await bootWithVault();
        await h.send({ type: 'LOCK' }, internalSender());
        const res = await h.send({ type: 'IMPORT_KEYS', accounts: [] }, internalSender());
        expect(res.success).toBe(false);
        expect(res.error).toMatch(/locked/i);
    });
});
