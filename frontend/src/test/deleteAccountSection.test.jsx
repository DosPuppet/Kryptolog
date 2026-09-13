/**
 * The danger zone's one irreversible option: "also remove this identity from
 * this device's vault".
 *
 * It is offered only when this device's vault is what holds the identity being
 * erased. With the keys in the TrustKeys extension, any vault on the device
 * belongs to a DIFFERENT identity — one this operation has no business
 * touching, and whose keys exist nowhere else (audit 2026-09-12 M-1). The
 * checkbox and the code acting on it therefore ask the SAME provider
 * predicate; asking it in only one of the two places is how the finding
 * happened.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, act, fireEvent } from '@testing-library/react';

const deleteServerAccount = vi.fn(async () => {});
const vaultHoldsCurrentIdentity = vi.fn(() => true);

vi.mock('../context/PQCContext', () => ({
    usePQC: () => ({ deleteServerAccount, vaultHoldsCurrentIdentity }),
}));
// Both dialogs are accepted, so the test reaches the request itself.
vi.mock('../utils/confirm', () => ({ default: vi.fn(async () => true) }));
vi.mock('../utils/toast', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const { default: DeleteAccountSection } = await import(
    '../components/dashboard/DeleteAccountSection'
);

const CHECKBOX = /remove this identity from this device/i;

/** Open the chooser and select a mode. The two radios are in MODES order. */
const MODE_RADIO = { leave: 0, erase: 1 };
const open = async (mode) => {
    render(<DeleteAccountSection />);
    await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /delete user/i }));
    });
    await act(async () => {
        fireEvent.click(screen.getAllByRole('radio')[MODE_RADIO[mode]]);
    });
};

const confirmDeletion = async () => {
    await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /continue/i }));
    });
};

beforeEach(() => {
    vi.clearAllMocks();
    vaultHoldsCurrentIdentity.mockReturnValue(true);
});

describe('when this device s vault holds the identity being erased', () => {
    it('offers the removal, checked, and asks for it', async () => {
        await open('erase');
        expect(screen.getByText(CHECKBOX)).toBeTruthy();

        await confirmDeletion();
        expect(deleteServerAccount).toHaveBeenCalledWith('erase', { forgetVault: true });
    });

    it('does not offer it for a leave — the vault is what makes that reversible', async () => {
        await open('leave');
        expect(screen.queryByText(CHECKBOX)).toBeNull();

        await confirmDeletion();
        expect(deleteServerAccount).toHaveBeenCalledWith('leave', { forgetVault: false });
    });
});

describe('when the identity lives in the extension instead', () => {
    beforeEach(() => vaultHoldsCurrentIdentity.mockReturnValue(false));

    it('does not offer to clear the vault', async () => {
        await open('erase');
        // Describing it as "this identity" would have been a lie, and acting on
        // it would have destroyed a different identity's only copy of its keys.
        expect(screen.queryByText(CHECKBOX)).toBeNull();
    });

    it('does not ask for it either, so the default cannot leak through', async () => {
        // The checkbox state defaults to true and is not rendered here, so a
        // request built from that state alone would still carry forgetVault.
        await open('erase');
        await confirmDeletion();
        expect(deleteServerAccount).toHaveBeenCalledWith('erase', { forgetVault: false });
    });
});
