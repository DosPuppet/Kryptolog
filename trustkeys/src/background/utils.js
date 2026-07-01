import { encryptVaultWithKey, deriveKey } from '../utils/crypto.js';
import { state, setSessionPassword } from './state.js';

export const saveVault = async (password) => {
    if (!state.vault) return;

    // Reuse the session's cached KDF key when saving under the session password,
    // so the deliberately-slow 600k-iter PBKDF2 runs once per unlock — not on
    // every account create/switch/delete. Only re-derive when there's no usable
    // cache (e.g. initial setup, or a save under a different password), and
    // cache the result when it matches the active session.
    let key = state.derivedKey;
    let salt = state.vaultSalt;
    if (!key || !salt || password !== state.sessionPassword) {
        salt = crypto.getRandomValues(new Uint8Array(16));
        key = await deriveKey(password, salt);
        if (password === state.sessionPassword) {
            state.derivedKey = key;
            state.vaultSalt = salt;
        }
    }

    const encryptionResult = await encryptVaultWithKey(state.vault, key, salt);
    await chrome.storage.local.set({ vaultData: encryptionResult });
    state.hasPassword = true;
};

export const launchPopup = async (route, params = {}) => {
    const queryString = new URLSearchParams({ route, ...params }).toString();
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

    await chrome.windows.create({
        url: `index.html?${queryString}`,
        type: 'popup',
        width,
        height,
        left,
        top,
        focused: true
    });
};

export const updateActivity = () => {
    if (!state.isLocked) {
        chrome.storage.session.set({ lastActive: Date.now() }).catch(() => { });
    }
}

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
