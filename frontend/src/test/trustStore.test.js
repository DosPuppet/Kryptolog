/**
 * Pinned contact keys travel with a backup (audit 2026-10-12 K-05).
 *
 * Both TOFU stores lived in localStorage only, so a restored backup or a new
 * device started every contact over as 'new' — and a key swapped meanwhile was
 * pinned without a word. The merge must let the LOCAL pin win: otherwise an old
 * or planted backup could make a changed key look unchanged.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
    trustContactKey, checkContactKey, exportTrustStores, importTrustStores,
} from '../services/trustedKeys';
import { vaultService } from '../services/vault';
import { generateMlDsaKeyPair, generateMlKemKeyPair } from '../utils/crypto';

const PASSWORD = 'correct horse battery staple';

beforeEach(() => localStorage.clear());

describe('importTrustStores', () => {
    it('adds the contacts this device has never seen', () => {
        trustContactKey('aa', 'key-a');
        const backup = exportTrustStores();
        localStorage.clear();

        importTrustStores(backup);
        expect(checkContactKey('aa', 'key-a')).toBe('unchanged');
        expect(checkContactKey('aa', 'key-swapped')).toBe('changed');
    });

    it('never overwrites a key this device already pinned', () => {
        trustContactKey('aa', 'key-a');
        importTrustStores({ keys: { aa: { key: 'key-from-backup', firstSeen: 1, updatedAt: 1 } } });
        expect(checkContactKey('aa', 'key-a')).toBe('unchanged');
        expect(checkContactKey('aa', 'key-from-backup')).toBe('changed');
    });

    it('ignores what is not a record', () => {
        importTrustStores({ keys: { aa: 'nope', '': { key: 'x' } }, attested: null });
        importTrustStores('garbage');
        expect(checkContactKey('aa', 'anything')).toBe('new');
        expect(exportTrustStores().keys).toEqual({});
    });
});

describe('a plaintext backup', () => {
    it('carries the pins to a clean device, and keeps them out of the vault itself', async () => {
        const dsa = await generateMlDsaKeyPair();
        const kem = await generateMlKemKeyPair();
        const exported = JSON.stringify({
            accounts: [{ name: 'me', mldsa: dsa, mlkem: kem }],
            trustStore: { keys: { bb: { key: 'key-b', firstSeen: 1, updatedAt: 1 } }, attested: {} },
        });

        await vaultService.importNewVault(exported, PASSWORD);
        expect(checkContactKey('bb', 'key-b')).toBe('unchanged');

        const reexported = JSON.parse(await vaultService.exportVault(PASSWORD));
        expect(reexported.trustStore.keys.bb.key).toBe('key-b');
        expect(Object.keys(reexported).sort()).toEqual(['accounts', 'activeAccountId', 'trustStore']);
    }, 30_000);
});
