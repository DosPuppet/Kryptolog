/**
 * The share dialog never asks the directory "who exists" (audit 2026-10-12 K-13).
 *
 * With an empty search box it used to call `GET /users?limit=10` — the very
 * listing the server no longer answers. Its default list is now the contacts
 * this device already pinned, each looked up by exact address.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { trustContactKey } from '../services/trustedKeys';

vi.mock('../context/AuthContext', () => ({
    useAuth: () => ({ token: 'tok', user: { address: 'me' } }),
}));

const { default: ShareModal } = await import('../components/dashboard/ShareModal');

const directory = {
    aa: { address: 'aa', username: 'alice', encryption_public_key: 'k-a' },
    bb: { address: 'bb', username: 'bob', encryption_public_key: 'k-b', deleted: true },
};

beforeEach(() => {
    localStorage.clear();
    global.fetch = vi.fn(async (url) => {
        const addr = String(url).match(/\/users\/([a-z]+)$/)?.[1];
        if (addr && directory[addr]) return { ok: true, status: 200, json: async () => directory[addr] };
        return { ok: true, status: 200, json: async () => [] };
    });
});

const open = async () => {
    await act(async () => {
        render(<ShareModal isOpen onClose={() => {}} secret={{ id: 1, name: 's' }} onShare={() => {}} />);
    });
    await act(async () => { await new Promise((r) => setTimeout(r, 600)); }); // the 500ms debounce
};

describe('ShareModal with nothing typed', () => {
    it('offers the pinned contacts, resolved by address, and never lists the directory', async () => {
        trustContactKey('aa', 'k-a');
        trustContactKey('bb', 'k-b');
        await open();

        const urls = global.fetch.mock.calls.map(([url]) => String(url));
        expect(urls.some((u) => /\/users(\?|$)/.test(u))).toBe(false);
        expect(urls.filter((u) => /\/users\/(aa|bb)$/.test(u))).toHaveLength(2);
        expect(screen.getByText('alice')).toBeTruthy();
        expect(screen.queryByText('bob')).toBeNull(); // deleted: nobody to wrap to
    });

    it('with no pinned contacts, asks nothing at all', async () => {
        await open();
        expect(global.fetch).not.toHaveBeenCalled();
        expect(screen.getByText(/Search by username, or paste an address/)).toBeTruthy();
    });
});
