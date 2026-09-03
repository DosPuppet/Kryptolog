// Unlocked-session persistence and the idle-lock policy (audit M-4).
//
// Three problems compounded here, and each one on its own defeated the lock:
//
//  1. The vault PASSWORD sat in plaintext in chrome.storage.session. It is the
//     PBKDF2 *input*, it survives a salt change, and it is the credential a
//     user is most likely to have reused elsewhere. We cache the DERIVED KEY's
//     raw bytes instead: equally powerful against THIS vault, worth nothing
//     anywhere else, and impossible to retype into another login. The bytes
//     have to be raw rather than a CryptoKey because chrome.storage.session is
//     JSON-serialized, not structured-clone, so a non-extractable CryptoKey
//     cannot survive a service-worker restart.
//
//  2. The idle check ran ONLY at service-worker startup. While the worker
//     stayed alive nothing re-checked, so "locks after an hour idle" really
//     meant "locks after an hour idle, if a restart happens to notice". A
//     chrome.alarms timer now runs the check on a schedule — alarms wake a
//     sleeping worker, which is the property this needs and the reason the
//     "alarms" permission is in the manifest.
//
//  3. updateActivity() ran at the top of onMessage for EVERY message, so any
//     connected page could hold the vault open indefinitely by pinging
//     GET_STATUS on a timer — no user present, no lock, ever. Activity now
//     means USER activity (a message from the extension's own pages); page
//     traffic never extends the session.

import { state } from './state.js';
import { toHex, fromHex } from '../utils/crypto.js';

export const IDLE_TIMEOUT_MS = 60 * 60 * 1000; // 1 hour
export const IDLE_ALARM = 'trustkeys-idle-lock';
// Alarms are clamped to >= 1 minute in released builds; the check is cheap, and
// a minute of granularity on an hour-long timeout is immaterial.
export const IDLE_CHECK_MINUTES = 1;

const SESSION_KEYS = ['vaultKeyHex', 'vaultSaltHex', 'lastActive'];

// chrome.storage.session is TRUSTED_CONTEXTS by default (content scripts cannot
// read it). Stated explicitly because the vault key lives here now — a silent
// default is a poor place to rest that. Guarded: setAccessLevel is Chrome-only
// and this extension also targets Firefox.
export const hardenSessionStorage = () => {
    try {
        chrome.storage.session.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });
    } catch { /* not supported here; the default is already trusted-only */ }
};

export const isExpired = (lastActive) =>
    typeof lastActive !== 'number' || (Date.now() - lastActive) >= IDLE_TIMEOUT_MS;

/** Persist the unlocked session: derived key bytes + salt, never the password. */
export const persistSession = async () => {
    if (!state.vaultKeyBytes || !state.vaultSalt) return;
    try {
        await chrome.storage.session.set({
            vaultKeyHex: toHex(state.vaultKeyBytes),
            vaultSaltHex: toHex(state.vaultSalt),
            lastActive: Date.now(),
        });
    } catch (e) { console.warn("Failed to persist session", e); }
};

export const clearSession = async () => {
    try {
        await chrome.storage.session.remove(SESSION_KEYS);
    } catch (e) { console.warn("Failed to clear session", e); }
};

/** The stored session, or null when absent/expired. Expired sessions are wiped. */
export const readSession = async () => {
    try {
        const s = await chrome.storage.session.get(SESSION_KEYS);
        if (!s.vaultKeyHex || !s.vaultSaltHex) return null;
        if (isExpired(s.lastActive)) {
            await clearSession();
            return null;
        }
        return { keyBytes: fromHex(s.vaultKeyHex), salt: fromHex(s.vaultSaltHex) };
    } catch (e) {
        console.warn("Session restore failed", e);
        return null;
    }
};

/**
 * Mark USER activity. Called only for messages from the extension's own pages —
 * see note 3 above; extending the session on page traffic is what made the
 * timeout unreachable.
 */
export const touchActivity = () => {
    if (state.isLocked) return;
    chrome.storage.session.set({ lastActive: Date.now() }).catch(() => { });
};

/** True when the session has gone idle and the vault should be locked. */
export const shouldIdleLock = async () => {
    if (state.isLocked) return false;
    try {
        const { lastActive } = await chrome.storage.session.get(['lastActive']);
        return isExpired(lastActive);
    } catch {
        // Can't tell how long it has been idle — lock rather than stay open.
        return true;
    }
};
