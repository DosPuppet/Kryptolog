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
import { generateAccount } from '../utils/crypto';

const PASSWORD = 'correct horse battery staple';
// Contacts are keyed by address: 96 hex since crypto-core 4.0.0.
const A = 'aa'.repeat(48);
const B = 'bb'.repeat(48);

beforeEach(() => localStorage.clear());

describe('importTrustStores', () => {
    it('adds the contacts this device has never seen', () => {
        trustContactKey(A, 'key-a');
        const backup = exportTrustStores();
        localStorage.clear();

        importTrustStores(backup);
        expect(checkContactKey(A, 'key-a')).toBe('unchanged');
        expect(checkContactKey(A, 'key-swapped')).toBe('changed');
    });

    it('never overwrites a key this device already pinned', () => {
        trustContactKey(A, 'key-a');
        importTrustStores({ keys: { [A]: { key: 'key-from-backup', firstSeen: 1, updatedAt: 1 } } });
        expect(checkContactKey(A, 'key-a')).toBe('unchanged');
        expect(checkContactKey(A, 'key-from-backup')).toBe('changed');
    });

    it('ignores what is not a record', () => {
        importTrustStores({ keys: { [A]: 'nope', '': { key: 'x' } }, attested: null });
        importTrustStores('garbage');
        expect(checkContactKey(A, 'anything')).toBe('new');
        expect(exportTrustStores().keys).toEqual({});
    });
});

describe('pins from before crypto-core 4.0.0', () => {
    // Keyed by a 2 624-hex ML-DSA-44 key, which names no identity any more: a
    // pin for nobody could only ever answer "changed" for somebody else.
    const OLD = 'cd'.repeat(1312);

    it('are ignored where they are stored', () => {
        localStorage.setItem('kryptolog_trusted_keys', JSON.stringify({
            [OLD]: { key: 'old', firstSeen: 1, updatedAt: 1 },
            [A]: { key: 'key-a', firstSeen: 1, updatedAt: 1 },
        }));
        expect(Object.keys(exportTrustStores().keys)).toEqual([A]);
    });

    it('are never imported from a backup', () => {
        importTrustStores({ keys: { [OLD]: { key: 'old', firstSeen: 1, updatedAt: 1 } } });
        expect(exportTrustStores().keys).toEqual({});
    });
});

describe('a plaintext backup', () => {
    it('carries the pins to a clean device, and keeps them out of the vault itself', async () => {
        const exported = JSON.stringify({
            accounts: [generateAccount('me')],
            trustStore: { keys: { [B]: { key: 'key-b', firstSeen: 1, updatedAt: 1 } }, attested: {} },
        });

        await vaultService.importNewVault(exported, PASSWORD);
        expect(checkContactKey(B, 'key-b')).toBe('unchanged');

        const reexported = JSON.parse(await vaultService.exportVault(PASSWORD));
        expect(reexported.trustStore.keys[B].key).toBe('key-b');
        expect(Object.keys(reexported).sort()).toEqual(['accounts', 'activeAccountId', 'trustStore']);
    }, 30_000);
});
