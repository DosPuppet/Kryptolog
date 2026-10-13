/**
 * A vault written by an older Kryptolog (crypto-core 3.x), on a 4.0.0 SPA.
 *
 * Its keys are ML-DSA-44 / ML-KEM-768 and open nothing any more. The vault
 * service used to turn every unlock failure into "Incorrect password", which
 * left such a device with no way forward at all: the screen offers only
 * "Unlock" while a vault is present, and every password was "wrong". It must
 * say what the vault is, and offer to remove it. Driven through the REAL vault
 * service, because the defect was in how its refusal reached the screen.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, act, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { newVaultKdf } from '../utils/crypto';

vi.mock('../utils/confirm', () => ({ default: vi.fn(async () => true) }));
vi.mock('../context/ThemeContext', () => ({
    useTheme: () => ({ theme: 'light', toggleTheme: () => { } }),
}));

const { PQCProvider } = await import('../context/PQCContext');
const { AuthProvider } = await import('../context/AuthContext');
const { vaultService } = await import('../services/vault');
const Login = (await import('../components/Login')).default;

const PASSWORD = 'correct horse battery staple';

beforeEach(() => {
    localStorage.clear();
    // What a 3.x SPA left behind: a format-3 blob. Nothing past its version
    // is ever read.
    localStorage.setItem('kryptolog_vault', JSON.stringify({
        v: 3, kdf: newVaultKdf(), iv: 'AAAAAAAAAAAAAAAA', data: 'AAAA',
    }));
    global.fetch = vi.fn(async () => ({ ok: true, json: async () => ({}) }));
});

describe('an older vault on this device', () => {
    it('is refused by name, not as a wrong password', async () => {
        await expect(vaultService.unlock(PASSWORD)).rejects.toThrow(/older Kryptolog version/);
    });

    it('is named on the login screen, which offers to remove it and start fresh', async () => {
        render(<MemoryRouter><AuthProvider><PQCProvider><Login /></PQCProvider></AuthProvider></MemoryRouter>);
        fireEvent.click(screen.getByText('Unlock Local Vault'));
        fireEvent.change(screen.getByPlaceholderText('Enter secure password'), { target: { value: PASSWORD } });
        await act(async () => { fireEvent.click(screen.getByText('Unlock & Connect')); });

        expect(screen.queryByText(/Incorrect password/)).toBeNull();
        expect(screen.getByText(/created by an older version of Kryptolog/)).toBeInTheDocument();

        await act(async () => { fireEvent.click(screen.getByText('Remove the old vault and start fresh')); });
        expect(localStorage.getItem('kryptolog_vault')).toBeNull();
        expect(vaultService.hasVault()).toBe(false);
    }, 30_000);
});
