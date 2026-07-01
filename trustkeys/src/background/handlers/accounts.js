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

// The currently-active account (with key material), or throws. Export is scoped
// to this single account: the extension uses random-UUID account ids, so a
// multi-account export loses the active selection when imported elsewhere (ids
// get remapped to the ML-DSA public key and the old activeAccountId no longer
// matches). Exporting just the active key keeps the imported identity unambiguous.
const requireActiveAccount = () => {
    const active = state.vault.accounts.find(a => a.id === state.vault.activeAccountId)
        || state.vault.accounts[0];
    if (!active) throw new Error("No active account to export");
    return active;
};

// Encrypted, portable backup (.kvault) of the ACTIVE account. Verifies the vault
// password as a gate, then encrypts a SPA-compatible vault shape
// ({accounts:[active], activeAccountId}) under a separate transfer passphrase
// using the SAME format the web app produces (encryptVault -> {salt, iv, data}),
// so it round-trips between extension and SPA.
export const exportEncryptedVault = async (password, passphrase) => {
    if (state.isLocked) throw new Error("Locked");
    if (!passphrase) throw new Error("Backup passphrase required");

    // Confirm the vault password (same gate as the plaintext export).
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");
    await decryptVault(vaultData, password); // throws on wrong password

    const active = requireActiveAccount();
    const portable = { accounts: [active], activeAccountId: active.id };
    const encrypted = await encryptVault(portable, passphrase);
    return JSON.stringify(encrypted);
};

// The active account only (with key material), password-gated. Backs the plain
// JSON export.
export const exportActiveAccount = async (password) => {
    if (state.isLocked) throw new Error("Locked");
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");
    await decryptVault(vaultData, password); // verify
    return requireActiveAccount();
};

// Import plaintext JSON ({accounts:[...]}) or an encrypted .kvault backup
// ({salt, iv, data}). `password` is the vault password used to re-save the merged
// vault; `passphrase` is the SEPARATE backup passphrase that decrypts a .kvault
// file (they are different secrets — a .kvault is encrypted under a transfer
// passphrase, not the vault password). Falls back to `password` when no
// passphrase is given (legacy callers that encrypted under the vault password).
export const importVault = async (vaultObj, password, passphrase) => {
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
        const secret = passphrase || password;
        if (!secret) throw new Error("Backup passphrase required for encrypted .kvault file");
        decryptedImport = await decryptVault(importedVault, secret);
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
