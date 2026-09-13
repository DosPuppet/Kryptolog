/**
 * Deleting the server-side account, from the provider down to the wire.
 *
 * Two modes, and the difference between them is not cosmetic: `leave` keeps
 * every row and can be undone by logging in again, `erase` removes the user's
 * content and blocks the key forever. The MODE is part of what gets signed, so
 * a relay cannot turn one into the other.
 *
 * The erase path also has to re-sign every message that carries a session key
 * other people's messages depend on. Those are read from a PAGED endpoint, and
 * reading only the first page would silently delete every carrier past it —
 * the quiet half of the O-3 paging trap, since nothing on screen would say a
 * page had been missed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';

const PASSWORD = 'correct horse battery staple';
const ADDRESS = 'a'.repeat(64);

const vault = {
    isLocked: false,
    hasVault: () => true,
    hasBiometrics: () => false,
    biometricMode: () => null,
    getCacheTTL: () => 0,
    clearKeyCache: vi.fn(),
    hasCachedKey: () => true, // no password prompt in the way of the assertions
    hasCachedSigningKey: () => true,
    unlock: vi.fn(async () => true),
    getActiveAccount: () => ({
        id: 'acct-1',
        name: 'Alice',
        mldsa: { publicKey: ADDRESS },
        mlkem: { publicKey: 'b'.repeat(64) },
    }),
    sign: vi.fn(async () => 'deletion-signature'),
    signMessage: vi.fn(async () => 'redaction-signature'),
    // Local-vault cleanup after an erase.
    getAccounts: vi.fn(() => [{ id: 'acct-1' }]),
    deleteAccount: vi.fn(async () => {}),
    wipeVault: vi.fn(),
};
vi.mock('../services/vault', () => ({ vaultService: vault }));

const { PQCProvider, usePQC } = await import('../context/PQCContext');
const { AuthProvider } = await import('../context/AuthContext');
const { accountDeletionBody, messageSigningBody } = await import('../utils/crypto');

let api;
function Probe() {
    api = usePQC();
    return null;
}

/** One page of the redaction manifest, as the server would serve it. */
const carrier = (id) => ({
    id,
    kind: 'dm',
    key: `dm:${id}`,
    conv: 'partner-address',
    gid: '',
    sid: `sid-${id}`,
    keys: { recip: { kem: 'k', iv: 'i', encKey: 'e' }, sender: null },
});

/** `total` carriers, served 100 per page the way utils/paging walks them. */
const stubServer = ({ total = 0 } = {}) => {
    global.fetch = vi.fn(async (url, init) => {
        const href = String(url);
        if (/redactable-messages/.test(href)) {
            const offset = Number(new URL(href).searchParams.get('offset'));
            const limit = Number(new URL(href).searchParams.get('limit'));
            const rows = Array.from({ length: total }, (_, i) => carrier(i + 1)).slice(
                offset,
                offset + limit
            );
            return { ok: true, status: 200, json: async () => rows };
        }
        if (/nonce/.test(href)) return { ok: true, status: 200, json: async () => ({ nonce: 'N' }) };
        if (/account\/delete/.test(href)) return { ok: true, status: 204, json: async () => null };
        return { ok: true, status: 200, json: async () => ({}) };
    });
    return global.fetch;
};

// By URL, not just "the first POST": mounting logs in first, and that is a
// POST with a body too.
const deleteCall = () =>
    global.fetch.mock.calls.find(([url]) => /account\/delete/.test(String(url)));

const deleteBody = () => JSON.parse(deleteCall()[1].body);

const mount = async () => {
    await act(async () => {
        render(
            <AuthProvider>
                <PQCProvider>
                    <Probe />
                </PQCProvider>
            </AuthProvider>
        );
    });
    // deleteServerAccount signs with the identity the provider is holding.
    await act(async () => {
        await api.loginLocalVault(PASSWORD);
    });
};

beforeEach(() => {
    vi.clearAllMocks();
    delete window.trustkeys;
    vault.hasCachedKey = () => true;
});
afterEach(() => {
    vi.restoreAllMocks();
});

describe('leaving', () => {
    it('sends the mode, redacts nothing, and logs out', async () => {
        stubServer();
        await mount();
        await act(async () => {
            await api.deleteServerAccount('leave');
        });

        const body = deleteBody();
        expect(body.mode).toBe('leave');
        expect(body.redactions).toEqual([]);
        // Leaving must not ask the server which messages carry a session key:
        // nothing is being deleted, so nothing needs re-signing.
        expect(global.fetch.mock.calls.some(([u]) => /redactable/.test(String(u)))).toBe(false);
    });

    it('signs the mode it is performing, not a fixed one', async () => {
        stubServer();
        await mount();
        await act(async () => {
            await api.deleteServerAccount('leave');
        });

        // Without the mode inside the signed body a relay could escalate this
        // into an erase — destroying data the user asked to keep — under a
        // signature the server accepts either way.
        expect(vault.sign).toHaveBeenCalledWith(await accountDeletionBody('N', 'leave', []), null);
    });
});

describe('erasing', () => {
    it('re-signs every carrier, across every page of the manifest', async () => {
        // 150 rows is two pages at the 100-row page size. A caller that read
        // only the first would delete the other 50 instead of redacting them.
        stubServer({ total: 150 });
        await mount();
        await act(async () => {
            await api.deleteServerAccount('erase');
        });

        const body = deleteBody();
        expect(body.mode).toBe('erase');
        expect(body.redactions).toHaveLength(150);
        expect(body.redactions[0]).toEqual({ key: 'dm:1', signature: 'redaction-signature' });
        expect(body.redactions.at(-1).key).toBe('dm:150');
    });

    it('signs the redacted form of each message, from the server-supplied conversation', async () => {
        stubServer({ total: 1 });
        await mount();
        await act(async () => {
            await api.deleteServerAccount('erase');
        });

        // ct: null is the redaction, and `conv` comes from the row the server
        // delivered the message under (audit F-1) — signing a conversation of
        // our own choosing would only produce a signature it rejects.
        const expected = await messageSigningBody({
            from: ADDRESS,
            conv: 'partner-address',
            gid: '',
            sid: 'sid-1',
            keys: carrier(1).keys,
            ct: null,
        });
        // No password argument: signMessage skips the prompt entirely once the
        // signing key is cached, which is what keeps a many-epoch erase silent.
        expect(vault.signMessage).toHaveBeenCalledWith(expected, undefined);
        expect(expected).toContain('\nredacted=1');
    });

    it('binds the whole redaction set into the deletion signature', async () => {
        stubServer({ total: 2 });
        await mount();
        await act(async () => {
            await api.deleteServerAccount('erase');
        });

        // Dropping one id en route turns that redaction into a deletion, which
        // takes the partner's own history with it.
        expect(vault.sign).toHaveBeenCalledWith(
            await accountDeletionBody('N', 'erase', ['dm:1', 'dm:2']),
            null
        );
    });

    it('does not delete anything when the signing step fails', async () => {
        stubServer({ total: 1 });
        vault.signMessage.mockRejectedValueOnce(new Error('user cancelled'));
        await mount();

        await expect(api.deleteServerAccount('erase')).rejects.toThrow('user cancelled');
        expect(global.fetch.mock.calls.some(([u]) => /account\/delete/.test(String(u)))).toBe(false);
    });
});

describe('what an erase leaves on the device', () => {
    // The key is blocked forever, so the vault entry left behind can only ever
    // be unlocked into a refusal — and while it is there the login screen
    // offers nothing but "Unlock Local Vault".
    it('removes only the erased identity when the vault holds others', async () => {
        vault.getAccounts.mockReturnValue([{ id: 'acct-1' }, { id: 'acct-2' }]);
        stubServer();
        await mount();
        await act(async () => {
            await api.deleteServerAccount('erase', { forgetVault: true });
        });

        // A vault can hold several identities and only one of them just became
        // useless. Wiping the lot would destroy keys the user still needs.
        expect(vault.deleteAccount).toHaveBeenCalledWith('acct-1', null);
        expect(vault.wipeVault).not.toHaveBeenCalled();
    });

    it('wipes the vault only when the erased identity was the last one', async () => {
        // deleteAccount refuses to remove the final account, and an empty but
        // present vault would still block the "create" path on the login screen.
        vault.getAccounts.mockReturnValue([{ id: 'acct-1' }]);
        stubServer();
        await mount();
        await act(async () => {
            await api.deleteServerAccount('erase', { forgetVault: true });
        });

        expect(vault.wipeVault).toHaveBeenCalledTimes(1);
        expect(vault.deleteAccount).not.toHaveBeenCalled();
    });

    it('touches nothing on the device unless asked', async () => {
        stubServer();
        await mount();
        await act(async () => {
            await api.deleteServerAccount('erase');
        });

        expect(vault.wipeVault).not.toHaveBeenCalled();
        expect(vault.deleteAccount).not.toHaveBeenCalled();
    });

    it('never touches the device on a leave — the vault is what makes it reversible', async () => {
        stubServer();
        await mount();
        await act(async () => {
            await api.deleteServerAccount('leave', { forgetVault: true });
        });

        expect(vault.wipeVault).not.toHaveBeenCalled();
        expect(vault.deleteAccount).not.toHaveBeenCalled();
    });
});

describe('an erase performed with the keys in the extension', () => {
    // A device can hold both: an identity in the TrustKeys extension, and a
    // separate one in a local vault that has never been unlocked this session.
    // withCustody prefers the extension, so the identity being erased is the
    // extension's — and the vault, being locked, reports no accounts at all,
    // which is what used to select "wipe the whole vault" (audit 2026-09-12
    // M-1). The keys it holds are a different, still-valid identity's, and they
    // exist nowhere else unless the user exported a backup.
    const EXTENSION_ADDRESS = 'e'.repeat(64);
    const localActiveAccount = vault.getActiveAccount;

    afterEach(() => {
        vault.isLocked = false;
        vault.getActiveAccount = localActiveAccount;
    });

    const mountWithExtension = async () => {
        window.trustkeys = {
            connect: vi.fn(async () => true),
            getAccount: vi.fn(async () => ({
                mldsaPublicKey: EXTENSION_ADDRESS,
                mlkemPublicKey: 'f'.repeat(64),
                name: 'ext-user',
            })),
            sign: vi.fn(async () => 'extension-signature'),
            signMessage: vi.fn(async () => 'extension-signature'),
        };
        // What vault.js answers while locked: no active account, no accounts.
        vault.isLocked = true;
        vault.getActiveAccount = () => null;
        vault.getAccounts.mockReturnValue([]);

        await act(async () => {
            render(
                <AuthProvider>
                    <PQCProvider>
                        <Probe />
                    </PQCProvider>
                </AuthProvider>
            );
        });
        await act(async () => {
            await api.loginTrustKeys();
        });
    };

    it('leaves a local vault holding another identity untouched', async () => {
        stubServer();
        await mountWithExtension();
        await act(async () => {
            await api.deleteServerAccount('erase', { forgetVault: true });
        });

        // The extension really was custody for this erase...
        expect(window.trustkeys.sign).toHaveBeenCalled();
        expect(vault.sign).not.toHaveBeenCalled();
        // ...so nothing on this device belonged to the erased identity.
        expect(vault.wipeVault).not.toHaveBeenCalled();
        expect(vault.deleteAccount).not.toHaveBeenCalled();
    });

    it('does not offer to clear a vault it is not holding', async () => {
        stubServer();
        await mountWithExtension();
        // The danger zone asks this before showing the checkbox, so the promise
        // on screen and what the code does cannot drift apart.
        expect(api.vaultHoldsCurrentIdentity()).toBe(false);
    });
});

describe('a vault open on a different identity', () => {
    const localActiveAccount = vault.getActiveAccount;
    afterEach(() => {
        vault.getActiveAccount = localActiveAccount;
    });

    it('is left alone, even though it is unlocked and has accounts', async () => {
        stubServer();
        await mount();
        // Unlocked, with an active account — just not the one being removed.
        // A "is the vault open?" check passes here; only comparing the ADDRESS
        // catches it, and the keys are not recoverable from a wrong guess.
        vault.getActiveAccount = () => ({
            id: 'acct-2',
            name: 'Bob',
            mldsa: { publicKey: 'c'.repeat(64) },
            mlkem: { publicKey: 'd'.repeat(64) },
        });
        vault.getAccounts.mockReturnValue([{ id: 'acct-1' }, { id: 'acct-2' }]);

        await expect(api.forgetLocalIdentity()).resolves.toBe('none');
        expect(vault.deleteAccount).not.toHaveBeenCalled();
        expect(vault.wipeVault).not.toHaveBeenCalled();
    });
});

describe('a login refused because the key was erased', () => {
    it('is tagged ACCOUNT_DELETED, not INVITE_REQUIRED', async () => {
        // Both used to arrive as 403, and the invite branch caught them both —
        // so an erased key told the user to enter an invite code for a key no
        // code could ever admit.
        global.fetch = vi.fn(async (url) =>
            /nonce/.test(String(url))
                ? { ok: true, status: 200, json: async () => ({ nonce: 'N' }) }
                : {
                    ok: false,
                    status: 410,
                    json: async () => ({ detail: 'This account was deleted and this key can no longer be used.' }),
                }
        );
        await act(async () => {
            render(
                <AuthProvider>
                    <PQCProvider>
                        <Probe />
                    </PQCProvider>
                </AuthProvider>
            );
        });

        await expect(api.loginLocalVault(PASSWORD)).rejects.toMatchObject({
            code: 'ACCOUNT_DELETED',
        });
    });
});
