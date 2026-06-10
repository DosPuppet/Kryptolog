import { generateAccount, decryptVault, encryptVault } from '../../utils/crypto.js';
import { state, getSessionPassword } from '../state.js';
import { saveVault } from '../utils.js';

export const createAccount = async (name) => {
    if (state.isLocked) throw new Error("Locked");

    const account = await generateAccount(name);
    state.vault.accounts.push(account);
    if (!state.vault.activeAccountId) state.vault.activeAccountId = account.id;

    await saveVault(getSessionPassword());
    return { id: account.id, name: account.name };
};

export const getAccounts = () => {
    if (state.isLocked) throw new Error("Locked");

    return state.vault.accounts.map(a => ({
        id: a.id,
        name: a.name,
        active: a.id === state.vault.activeAccountId
    }));
};

export const setActiveAccount = async (id) => {
    if (state.isLocked) throw new Error("Locked");
    state.vault.activeAccountId = id;
    await saveVault(getSessionPassword());
};

export const getActiveAccount = (checkOrigin) => {
    if (state.isLocked) throw new Error("Locked");

    // checkOrigin is null only for the internal dashboard (trusted). For external
    // callers it's the authoritative sender.origin, which must be connected.
    if (checkOrigin && !state.vault.permissions[checkOrigin]) {
        throw new Error("Not Connected");
    }

    const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
    if (!account) throw new Error("No active account");

    return {
        name: account.name,
        kyberPublicKey: account.kyber.publicKey,
        dilithiumPublicKey: account.dilithium.publicKey
    };
};

export const exportVault = async (password) => {
    if (state.isLocked) throw new Error("Locked");

    // We use the state.vault directly since it's already decrypted
    // But we verify the password first to be safe (as per original logic)
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");
    await decryptVault(vaultData, password);

    return state.vault;
};

export const importVault = async (vaultObj, password) => {
    let importedVault = vaultObj;
    if (typeof importedVault === 'string') {
        try {
            importedVault = JSON.parse(importedVault);
        } catch (e) {
            throw new Error("Invalid import format (not JSON)");
        }
    }

    // Check if it's already encrypted (has salt) or plaintext (has accounts)
    let decryptedImport;
    if (importedVault && !importedVault.salt && Array.isArray(importedVault.accounts)) {
        decryptedImport = importedVault;
    } else {
        decryptedImport = await decryptVault(importedVault, password);
    }

    if (!decryptedImport.accounts || !Array.isArray(decryptedImport.accounts)) {
        throw new Error("Invalid vault data: missing accounts");
    }

    // MERGE logic: Keep existing, add new ones if ID doesn't exist
    if (!state.vault) {
        // Fallback for fresh install/first import
        state.vault = decryptedImport;
    } else {
        const existingIds = new Set(state.vault.accounts.map(a => a.id));
        let addedCount = 0;

        for (const account of decryptedImport.accounts) {
            if (!existingIds.has(account.id)) {
                state.vault.accounts.push(account);
                addedCount++;
            }
        }
    }

    if (!state.vault.permissions) state.vault.permissions = {};
    state.hasPassword = true;
    state.isLocked = false;

    // Save cleanly
    await saveVault(password);

    return true;
};

export const deleteAccount = async (id) => {
    if (state.isLocked) throw new Error("Locked");

    const index = state.vault.accounts.findIndex(a => a.id === id);
    if (index === -1) throw new Error("Account not found");

    // Remove the account
    state.vault.accounts.splice(index, 1);

    // If we deleted the active account, pick another one
    if (state.vault.activeAccountId === id) {
        if (state.vault.accounts.length > 0) {
            state.vault.activeAccountId = state.vault.accounts[0].id;
        } else {
            state.vault.activeAccountId = null;
        }
    }

    await saveVault(getSessionPassword());
    return true;
};
