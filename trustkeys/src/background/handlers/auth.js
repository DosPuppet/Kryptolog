import { decryptVault } from '../../utils/crypto.js';
import { state, setSessionPassword, getSessionPassword } from '../state.js';
import { saveVault } from '../utils.js';

export const setupPassword = async (password) => {
    if (state.hasPassword) throw new Error("Password already set");

    state.vault = { accounts: [], activeAccountId: null, permissions: {} };
    await saveVault(password);
    state.isLocked = false;
    return true;
};

export const unlock = async (password) => {
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");

    try {
        state.vault = await decryptVault(vaultData, password);
        // Migration: Ensure permissions object exists
        if (!state.vault.permissions) state.vault.permissions = {};

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
