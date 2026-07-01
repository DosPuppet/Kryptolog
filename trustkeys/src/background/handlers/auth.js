import { fromHex, deriveKey, decryptVaultWithKey } from '../../utils/crypto.js';
import { state, setSessionPassword } from '../state.js';
import { saveVault } from '../utils.js';

export const setupPassword = async (password) => {
    if (state.hasPassword) throw new Error("Password already set");

    state.vault = { accounts: [], activeAccountId: null, permissions: {}, autoSignSites: {} };
    await saveVault(password);
    state.isLocked = false;
    return true;
};

export const unlock = async (password) => {
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");

    try {
        // Derive the KDF key ONCE here and cache it for the session, so every
        // subsequent saveVault (account switch/create/delete) reuses it instead
        // of re-running the deliberately-slow 600k-iter PBKDF2.
        const salt = fromHex(vaultData.salt);
        const key = await deriveKey(password, salt);
        state.vault = await decryptVaultWithKey(vaultData, key); // throws on wrong password
        state.derivedKey = key;
        state.vaultSalt = salt;
        // Migration: Ensure permissions + per-site capability objects exist
        if (!state.vault.permissions) state.vault.permissions = {};
        if (!state.vault.autoSignSites) state.vault.autoSignSites = {};

        state.isLocked = false;
        return true;
    } catch (e) {
        console.error("Unlock failed", e);
        return false;
    }
};

export const lock = () => {
    state.vault = null;
    state.isLocked = true;
    state.derivedKey = null;
    state.vaultSalt = null;
};

export const unlockWithSession = async (password) => {
    const success = await unlock(password);
    if (success) {
        setSessionPassword(password);
        try {
            await chrome.storage.session.set({
                sessionPassword: password,
                lastActive: Date.now()
            });
        } catch (e) { console.warn("Failed to persist session", e); }
    }
    return success;
};

export const lockWithSession = async () => {
    lock();
    setSessionPassword(null);
    try {
        await chrome.storage.session.remove(['sessionPassword', 'lastActive']);
    } catch (e) { console.warn("Failed to clear session", e); }
};
