import { generateAccount, decryptVault, encryptVault, parseAccount, isEncryptedVaultBlob, vaultPasswordProblem } from '../../utils/crypto.js';
import { state, requireUnlocked, requireActiveAccount } from '../state.js';
import { saveVault, saveVaultWithSessionKey } from '../utils.js';

export const createAccount = async (name) => {
    requireUnlocked();

    const account = generateAccount(name);
    state.vault.accounts.push(account);
    if (!state.vault.activeAccountId) state.vault.activeAccountId = account.id;

    await saveVaultWithSessionKey();
    return { id: account.id, name: account.name };
};

export const getAccounts = () => {
    requireUnlocked();

    return state.vault.accounts.map(a => ({
        id: a.id,
        name: a.name,
        active: a.id === state.vault.activeAccountId
    }));
};

export const setActiveAccount = async (id) => {
    requireUnlocked();
    state.vault.activeAccountId = id;
    await saveVaultWithSessionKey();
};

export const getActiveAccount = (checkOrigin) => {
    requireUnlocked();

    // checkOrigin is null only for the internal dashboard (trusted). For external
    // callers it's the authoritative sender.origin, which must be connected.
    if (checkOrigin && !state.vault.permissions[checkOrigin]) {
        throw new Error("Not Connected");
    }

    const account = requireActiveAccount();

    // The address, the identity key it names, and the encryption key, each
    // under its own name (crypto-core 3.3.0). An account's id IS its address
    // since 4.0.0, so the address is not recomputed here.
    return {
        name: account.name,
        address: account.id,
        identityPublicKey: account.identity.publicKey,
        encryptionPublicKey: account.encryption.publicKey,
    };
};

// The currently-active account (with key material), or throws. Export is scoped
// to this single account, which keeps the imported identity unambiguous. (It
// began as a workaround for the extension's random-UUID account ids, gone
// since crypto-core 4.0.0 made an account's id its address in both apps; the
// scope stayed because one identity per export is still the clearer artifact.)
// Deliberately not state.requireActiveAccount: this one falls back to the
// first account and says "to export", because a vault whose active selection
// was somehow lost should still be recoverable through a backup.
const accountForExport = () => {
    const active = state.vault.accounts.find(a => a.id === state.vault.activeAccountId)
        || state.vault.accounts[0];
    if (!active) throw new Error("No active account to export");
    return active;
};

// Encrypted, portable backup (.kvault) of the ACTIVE account. Verifies the vault
// password as a gate, then encrypts a SPA-compatible vault shape
// ({accounts:[active], activeAccountId}) under a separate transfer passphrase
// using the SAME format the web app produces (encryptVault -> {v, kdf, iv, data}),
// so it round-trips between extension and SPA.
export const exportEncryptedVault = async (password, passphrase) => {
    requireUnlocked();
    if (!passphrase) throw new Error("Backup passphrase required");
    // The .kvault is attacked offline once it leaves the device (K-08).
    const problem = vaultPasswordProblem(passphrase);
    if (problem) throw new Error(problem);

    // Confirm the vault password (same gate as the plaintext export).
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");
    await decryptVault(vaultData, password); // throws on wrong password

    const active = accountForExport();
    const portable = { accounts: [active], activeAccountId: active.id };
    const encrypted = await encryptVault(portable, passphrase);
    return JSON.stringify(encrypted);
};

// The active account only (with key material), password-gated. Backs the plain
// JSON export.
export const exportActiveAccount = async (password) => {
    requireUnlocked();
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");
    await decryptVault(vaultData, password); // verify
    return accountForExport();
};

// Import plaintext JSON ({accounts:[...]}) or an encrypted .kvault backup
// ({v, kdf, iv, data}). `password` is the vault password used to re-save the merged
// vault; `passphrase` is the SEPARATE backup passphrase that decrypts a .kvault
// file (they are different secrets — a .kvault is encrypted under a transfer
// passphrase, not the vault password). Falls back to `password` when no
// passphrase is given (legacy callers that encrypted under the vault password).
export const importVault = async (vaultObj, password, passphrase) => {
    let importedVault = vaultObj;
    if (typeof importedVault === 'string') {
        try {
            importedVault = JSON.parse(importedVault);
        } catch {
            throw new Error("Invalid import format (not JSON)");
        }
    }

    // Encrypted backup, current or older format (the older one then gets
    // crypto-core's readable "older version" refusal), or plaintext accounts.
    let decryptedImport;
    if (!isEncryptedVaultBlob(importedVault) && Array.isArray(importedVault?.accounts)) {
        decryptedImport = importedVault;
    } else {
        const secret = passphrase || password;
        if (!secret) throw new Error("Backup passphrase required for encrypted .kvault file");
        decryptedImport = await decryptVault(importedVault, secret);
    }

    if (!decryptedImport.accounts || !Array.isArray(decryptedImport.accounts)) {
        throw new Error("Invalid vault data: missing accounts");
    }

    // Re-derived from their seeds (crypto-core 4.0.0): an older backup is
    // refused by name, and an account whose keys or id disagree is refused.
    decryptedImport.accounts = decryptedImport.accounts.map(parseAccount);

    // MERGE logic: keep existing, add new ones. Deduplicated by id, which is
    // the ADDRESS in both apps now — an identity exported from the SPA and
    // already here is recognised as the same one (it was a second copy when
    // the extension gave accounts UUIDs).
    if (!state.vault) {
        // Fallback for fresh install/first import
        state.vault = decryptedImport;
    } else {
        const existingIds = new Set(state.vault.accounts.map(a => a.id));

        for (const account of decryptedImport.accounts) {
            if (!existingIds.has(account.id)) {
                state.vault.accounts.push(account);
            }
        }
    }

    if (!state.vault.permissions) state.vault.permissions = {};
    state.hasPassword = true;
    state.isLocked = false;

    // Save cleanly. A password is present only when the caller supplied one for
    // this import; otherwise re-seal under the unlocked session's key, which is
    // what removed the need to keep the password around at all (audit M-4).
    if (password) await saveVault(password);
    else await saveVaultWithSessionKey();

    return true;
};

export const deleteAccount = async (id) => {
    requireUnlocked();

    const index = state.vault.accounts.findIndex(a => a.id === id);
    if (index === -1) throw new Error("Account not found");

    state.vault.accounts.splice(index, 1);

    // The vault must never be left pointing at an account that is gone.
    if (state.vault.activeAccountId === id) {
        if (state.vault.accounts.length > 0) {
            state.vault.activeAccountId = state.vault.accounts[0].id;
        } else {
            state.vault.activeAccountId = null;
        }
    }

    await saveVaultWithSessionKey();
    return true;
};
