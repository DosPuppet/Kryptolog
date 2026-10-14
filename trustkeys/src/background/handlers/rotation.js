// Replacing the active identity's encryption key (crypto-core 5.1.0).
//
// A connected page asks; the user approves in a window that says what will
// happen; the extension rotates, SAVES the vault, and only then hands back the
// new key, its attestation and the signed rotation for the page to publish —
// the server must never serve a key this vault could lose. The identity seed
// never leaves this file's functions.
//
// Undoing is for a rotation the server REFUSED, and is safe by construction:
// crypto-core keeps the unpublished key retired rather than dropping it, so
// even a page calling it at the wrong moment destroys nothing. It is still
// narrowed to the rotation just made, from the page that asked, for a few
// minutes — a page has no business shuffling which key is current.

import {
    rotateAccountEncryptionKey, revertAccountEncryptionKeyRotation, destroyRetiredEncryptionKey,
    attestEncryptionKey, signKeyRotation,
} from '../../utils/crypto.js';
import { state, requireUnlocked, requireActiveAccount, activeAccount, requireConnectedOrigin } from '../state.js';
import { getSenderOrigin, saveVaultWithSessionKey } from '../utils.js';
import { requestApproval } from '../approvals.js';

// The window in which the page that rotated may undo it, and how far the
// page's clock may sit from ours (the server allows 10 minutes too).
const UNDO_WINDOW_MS = 5 * 60 * 1000;
const CLOCK_SKEW_MS = 10 * 60 * 1000;

const replaceActive = async (account) => {
    const index = state.vault.accounts.findIndex((a) => a.id === account.id);
    state.vault.accounts[index] = account;
    await saveVaultWithSessionKey();
};

export const handleRotateEncryptionKeyAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const origin = getSenderOrigin(sender);
    requireConnectedOrigin(origin);
    const { ts } = request;
    if (!Number.isSafeInteger(ts) || ts < 0 || Math.abs(Date.now() - ts) > CLOCK_SKEW_MS) {
        throw new Error("Invalid rotation timestamp");
    }
    const account = requireActiveAccount();

    await requestApproval({
        type: 'SIGN',
        origin,
        data: {
            origin,
            kind: 'key-rotation',
            details: { address: account.id, retired: account.retiredEncryption?.length ?? 0 },
            account: account.name,
            message: 'A new encryption key is created in TrustKeys and published by the site. ' +
                'The current one is kept, retired, to read older history.',
        },
        route: 'sign',
        onApprove: async () => {
            const active = activeAccount();
            if (!active || active.id !== account.id) {
                return sendResponse({ success: false, error: "The active account changed" });
            }
            const rotated = rotateAccountEncryptionKey(active, ts);
            await replaceActive(rotated);
            state.pendingRotation = { origin, newKid: rotated.encryption.kid, at: Date.now() };
            const seed = active.identity.seed;
            sendResponse({
                success: true,
                result: {
                    encryptionPublicKey: rotated.encryption.publicKey,
                    oldKid: active.encryption.kid,
                    newKid: rotated.encryption.kid,
                    attestation: await attestEncryptionKey(
                        { address: active.id, encryptionPublicKey: rotated.encryption.publicKey }, seed
                    ),
                    signature: await signKeyRotation(
                        { address: active.id, oldKid: active.encryption.kid, newKid: rotated.encryption.kid, ts },
                        seed
                    ),
                },
            });
        },
        onReject: (err) => sendResponse({ success: false, error: err }),
    });
};

export const handleRevertEncryptionKeyRotation = async ({ request, origin }) => {
    requireUnlocked();
    const pending = state.pendingRotation;
    if (!pending || pending.origin !== origin || pending.newKid !== request.newKid ||
        Date.now() - pending.at > UNDO_WINDOW_MS) {
        throw new Error("There is no rotation from this site to undo");
    }
    state.pendingRotation = null;
    await replaceActive(revertAccountEncryptionKeyRotation(requireActiveAccount(), request.newKid));
    return { success: true };
};

// Extension pages only: destroying a retired key is the user's decision, made
// in TrustKeys, never a site's.
export const handleDestroyRetiredEncryptionKey = async ({ request }) => {
    requireUnlocked();
    await replaceActive(destroyRetiredEncryptionKey(requireActiveAccount(), request.kid));
    return { success: true };
};
