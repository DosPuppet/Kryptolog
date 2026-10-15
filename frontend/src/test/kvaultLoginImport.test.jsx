/**
 * An encrypted .kvault backup, imported from the login screen.
 *
 * Reported as "the app says there's no key": the backup downloads as
 * `.kvault.json` (Chrome fixes an unknown extension to match the
 * application/json type it was saved under), so the login screen's
 * "Import existing vault (.json)" accepted it — and handed it to the
 * PLAINTEXT importer, which found no `accounts` and said "no accounts found".
 * The file was fine; only /receive's "Backup file" tab could open it.
 *
 * Driven through the REAL vault service with a genuine encrypted blob, since
 * the defect was which importer the screen picked for it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, act, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { encryptVault, generateAccount } from '../utils/crypto';

vi.mock('../context/ThemeContext', () => ({
    useTheme: () => ({ theme: 'light', toggleTheme: () => { } }),
}));

const { PQCProvider } = await import('../context/PQCContext');
const { AuthProvider } = await import('../context/AuthContext');
const { vaultService } = await import('../services/vault');
const Login = (await import('../components/Login')).default;

const PASSPHRASE = 'backup passphrase for transport';
const DEVICE_PASSWORD = 'correct horse battery staple';

let me;
let kvault;

beforeEach(async () => {
    localStorage.clear();
    delete window.trustkeys;
    me = generateAccount('me');
    kvault = JSON.stringify(await encryptVault({ accounts: [me], activeAccountId: me.id }, PASSPHRASE));
    global.fetch = vi.fn(async (url) => {
        if (/nonce/i.test(String(url))) return { ok: true, json: async () => ({ nonce: 'ab12', deployment: 'dev' }) };
        return { ok: true, json: async () => ({ user: { address: me.id }, access_token: 't' }) };
    });
}, 30_000);

const pickFile = async (text, name) => {
    const input = document.querySelector('input[type="file"]');
    await act(async () => {
        fireEvent.change(input, { target: { files: [new File([text], name, { type: 'application/json' })] } });
        // FileReader settles on a later tick.
        await new Promise(r => setTimeout(r, 50));
    });
};

describe('an encrypted backup on the login screen', () => {
    it('is recognised by its content, asks for its passphrase, and opens', async () => {
        render(<MemoryRouter><AuthProvider><PQCProvider><Login /></PQCProvider></AuthProvider></MemoryRouter>);
        fireEvent.click(screen.getByText(/Import existing vault/));
        await pickFile(kvault, 'kryptolog-keys-1.kvault.json');

        fireEvent.change(screen.getByPlaceholderText('The passphrase chosen when exporting'), { target: { value: PASSPHRASE } });
        fireEvent.change(screen.getByPlaceholderText('Set a password for this vault'), { target: { value: DEVICE_PASSWORD } });
        await act(async () => { fireEvent.click(screen.getByText('Import & Connect')); });

        // Two Argon2id derivations (open the backup, seal the device vault).
        await waitFor(() => expect(vaultService.hasVault()).toBe(true), { timeout: 20_000 });
        expect(screen.queryByText(/no accounts found/)).toBeNull();
        expect(vaultService.getActiveAccount().id).toBe(me.id);
        // Sealed under the DEVICE password now, not the transport passphrase.
        vaultService.lock();
        await expect(vaultService.unlock(DEVICE_PASSWORD)).resolves.toBe(true);
    }, 30_000);

    it('is refused by name by the plaintext importer, not as a file without accounts', async () => {
        await expect(vaultService.importNewVault(kvault, DEVICE_PASSWORD))
            .rejects.toThrow(/encrypted \.kvault backup/);
        expect(vaultService.hasVault()).toBe(false);
    });
});
