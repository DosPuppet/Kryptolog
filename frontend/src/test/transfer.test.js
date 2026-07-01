import { describe, it, expect } from 'vitest';
import { generateTransferCode, encryptVault, decryptVault } from '../utils/crypto';
import { packHandoff, unpackHandoff } from '../services/transfer';

describe('device key transfer helpers', () => {
    it('generateTransferCode produces grouped Crockford-base32', () => {
        const code = generateTransferCode();
        // 128 bits -> 26 base32 chars -> grouped in 4s with dashes.
        expect(code.replace(/-/g, '')).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
        expect(code.replace(/-/g, '').length).toBeGreaterThanOrEqual(26);
        expect(generateTransferCode()).not.toBe(code); // random
    });

    it('packHandoff / unpackHandoff round-trips (passphrase may contain dashes)', () => {
        const id = 'AbC123xyz';
        const pass = generateTransferCode(); // contains dashes
        const packed = packHandoff(id, pass);
        const out = unpackHandoff(packed);
        expect(out).toEqual({ id, passphrase: pass });
    });

    it('unpackHandoff rejects malformed input', () => {
        expect(unpackHandoff('')).toBeNull();
        expect(unpackHandoff('nodot')).toBeNull();
        expect(unpackHandoff('.leadingdot')).toBeNull();
    });

    it('encrypted vault blob round-trips with the transfer passphrase', async () => {
        const vault = { accounts: [{ id: 'a', name: 'A', kyber: { privateKey: 'ab' }, dilithium: { privateKey: 'cd' } }], activeAccountId: 'a' };
        const pass = generateTransferCode();
        const blob = await encryptVault(vault, pass);
        // Server-relayed/serialized form.
        const restored = await decryptVault(JSON.parse(JSON.stringify(blob)), pass);
        expect(restored).toEqual(vault);
    });

    it('wrong passphrase fails to decrypt the blob', async () => {
        const blob = await encryptVault({ accounts: [], activeAccountId: null }, generateTransferCode());
        await expect(decryptVault(blob, generateTransferCode())).rejects.toThrow();
    });
});
