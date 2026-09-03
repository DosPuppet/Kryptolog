import { encryptVaultWithKey, deriveVaultKeyBits, importVaultKey } from '../utils/crypto.js';
import { state } from './state.js';
import { persistSession } from './session.js';

const writeVault = async (key, salt) => {
    const encryptionResult = await encryptVaultWithKey(state.vault, key, salt);
    await chrome.storage.local.set({ vaultData: encryptionResult });
    state.hasPassword = true;
};

/**
 * Save under a freshly derived key. Only for the two places that legitimately
 * hold a password — initial setup and vault import — because it pays the
 * deliberately-slow 600k-iteration PBKDF2 every time.
 *
 * Re-caches the result as the session key, so the in-memory key never goes stale
 * against the salt just written to disk.
 */
export const saveVault = async (password) => {
    if (!state.vault) return;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyBytes = await deriveVaultKeyBits(password, salt);
    const key = await importVaultKey(keyBytes);

    await writeVault(key, salt);

    state.vaultKey = key;
    state.vaultKeyBytes = keyBytes;
    state.vaultSalt = salt;
    await persistSession();
};

/**
 * Save using the unlocked session's cached key — every other call site
 * (account create/switch/delete, permission changes).
 *
 * This is what replaced `saveVault(getSessionPassword())` (audit M-4): those
 * eight call sites were the whole reason the password had to be kept around at
 * all. With the key cached instead, none of them needs it.
 */
export const saveVaultWithSessionKey = async () => {
    if (!state.vault) return;
    if (!state.vaultKey || !state.vaultSalt) {
        throw new Error("Vault is locked");
    }
    await writeVault(state.vaultKey, state.vaultSalt);
};

/**
 * Open the extension popup (not an approval — see approvals.js for those).
 * Reuses the tracked window so a locked site calling CONNECT in a loop focuses
 * one window instead of spawning an OS window per call (audit M-6).
 */
export const launchPopup = async (route, params = {}) => {
    if (state.popupWindowId !== null) {
        try {
            await chrome.windows.update(state.popupWindowId, { focused: true });
            return;
        } catch {
            state.popupWindowId = null;
        }
    }

    const queryString = new URLSearchParams(route ? { route, ...params } : params).toString();
    const width = 360;
    const height = 600;
    let left, top;

    try {
        // Attempt to position in top-right of current window
        const lastWin = await chrome.windows.getLastFocused();
        if (lastWin && lastWin.left !== undefined && lastWin.width !== undefined) {
            // Position: Right side with 20px padding, Top with 80px padding (account for toolbar)
            left = lastWin.left + lastWin.width - width - 20;
            top = lastWin.top + 80;
        }
    } catch (e) {
        // Fallback to OS default if we can't get window info
        console.warn("Failed to calculate popup position", e);
    }

    try {
        const win = await chrome.windows.create({
            url: queryString ? `index.html?${queryString}` : 'index.html',
            type: 'popup',
            width,
            height,
            left,
            top,
            focused: true
        });
        state.popupWindowId = win?.id ?? null;
    } catch (e) {
        console.warn("Failed to open popup", e);
    }
};

// --- Sender trust (audit M4) ---
// Authorization decisions MUST use the origin Chrome attaches to the message
// sender (sender.origin / sender.url), never an origin carried in the message
// payload (request.origin) — the page-facing code can set the latter, so it
// must not be trusted for permission checks.

// True only for the extension's own pages (popup / dashboard index.html).
// Note: content scripts also have sender.id === chrome.runtime.id, so the id
// alone is NOT sufficient — we additionally require the extension-page URL.
export const isInternalSender = (sender) =>
    !!sender && sender.id === chrome.runtime.id &&
    !!sender.url && sender.url.includes('index.html');

// The authoritative origin of the sender, or null if Chrome didn't provide one
// (in which case callers must deny, not fall back to a payload-supplied origin).
export const getSenderOrigin = (sender) => (sender && sender.origin) ? sender.origin : null;

// Dev origins: served over http on localhost and covered by the STATIC manifest
// content_scripts, so they need no optional host permission and are exempt from
// the HTTPS-only rule for user-added trusted sites.
export const isDevOrigin = (origin) =>
    !!origin && (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1'));

// A production trusted site must be HTTPS (a network attacker could inject script
// into a plain-http origin and inherit its access to the user's keys).
export const isAllowedTrustedOrigin = (origin) => {
    if (!origin) return false;
    if (isDevOrigin(origin)) return true;
    return origin.startsWith('https://');
};
