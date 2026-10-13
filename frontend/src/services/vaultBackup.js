import { encryptVault, decryptVault, parseAccount, isEncryptedVaultBlob, vaultPasswordProblem } from '../utils/crypto';
import { exportTrustStores, importTrustStores } from './trustedKeys';

// One rule for every password that seals keys (crypto-core 3.0.0, audit
// 2026-10-12 K-08): the floor here was 6 characters. Throws the rule's own
// user-facing reason.
const requireStrongPassword = (password) => {
    const problem = vaultPasswordProblem(password);
    if (problem) throw new Error(problem);
};

// Backup / transfer / import-export methods for VaultService. Defined here and
// merged onto VaultService.prototype in vault.js — `this` is the singleton, so
// they share _getFullVault/_save/_sanitize with the core class.
export const backupMethods = {

    // Create a BRAND-NEW local vault from an exported backup (.json from
    // exportVault). Used on a clean device where no vault exists yet. The backup
    // holds plaintext accounts; we re-encrypt them under a new local password.
    async importNewVault(jsonString, password) {
        if (this.hasVault()) {
            throw new Error("A vault already exists on this device. Import accounts from Settings instead.");
        }
        requireStrongPassword(password);

        let data;
        try {
            data = JSON.parse(jsonString);
        } catch {
            throw new Error("Invalid file: not valid JSON");
        }
        if (!data.accounts || !Array.isArray(data.accounts) || data.accounts.length === 0) {
            throw new Error("Invalid vault file: no accounts found");
        }
        // Same reason as setup(): the old registration wraps the old vault's
        // password. importEncryptedBlob comes through here too, so both
        // clean-device paths are covered. importVault does NOT clear it — that
        // merges into the existing vault under its existing password, which the
        // registration still opens.
        this.disableBiometrics();
        // Re-derived from their seeds (crypto-core 4.0.0): an account whose
        // stored keys or id disagree with them is refused, and so is a backup
        // an older Kryptolog wrote — by name. The id is the address.
        const accounts = data.accounts.map(parseAccount);

        const activeAccountId = (data.activeAccountId &&
            accounts.some(a => a.id === data.activeAccountId))
            ? data.activeAccountId
            : accounts[0].id;

        const fullVault = { accounts, activeAccountId };

        // Encrypt + persist under the new password, then expose sanitized in memory.
        await this._save(fullVault, password);
        // The contacts' pinned keys came along (audit 2026-10-12 K-05). Kept
        // OUT of fullVault: they are not key material and the vault only
        // ever stores accounts.
        importTrustStores(data.trustStore);
        this.vault = {
            accounts: fullVault.accounts.map(acc => this._sanitize(acc)),
            activeAccountId
        };
        this.isLocked = false;

        const active = fullVault.accounts.find(a => a.id === activeAccountId);
        return this._sanitize(active);
    },

    async exportVault(password) {
        if (this.isLocked) throw new Error("Vault locked");
        const fullVault = await this._getFullVault(password);
        // Export plaintext (sensitive!). The pinned contact keys travel with
        // it, so a restore does not start every contact over as 'new' (K-05).
        return JSON.stringify({ ...fullVault, trustStore: exportTrustStores() }, null, 2);
    },

    // --- Device-to-device transfer ---
    // Produce an ENCRYPTED vault blob (the full vault, AES-GCM under a one-time
    // transfer passphrase). Used for both the downloadable encrypted-backup file
    // and the server relay — the passphrase is carried out of band, never sent
    // to the server. `vaultPassword` may be null when a derived key is cached.
    async exportEncryptedBlob(transferPassphrase, vaultPassword) {
        if (this.isLocked) throw new Error("Vault locked");
        if (!transferPassphrase) throw new Error("Transfer passphrase required");
        // The generated 128-bit transfer code passes this; a passphrase a
        // person picked for a .kvault backup has to, too — the file is attacked
        // offline once it leaves the device.
        requireStrongPassword(transferPassphrase);
        const fullVault = await this._getFullVault(vaultPassword);
        const encrypted = await encryptVault({ ...fullVault, trustStore: exportTrustStores() }, transferPassphrase);
        return JSON.stringify(encrypted);
    },

    // Consume an encrypted vault blob produced by exportEncryptedBlob on another
    // device: decrypt with the transfer passphrase, then re-encrypt locally under
    // a fresh device password. Clean-device flow (creates a new local vault).
    async importEncryptedBlob(blobString, transferPassphrase, newLocalPassword) {
        if (this.hasVault()) {
            throw new Error("A vault already exists on this device. Import from the Vault Manager while signed in.");
        }
        requireStrongPassword(newLocalPassword);
        let encrypted;
        try {
            encrypted = JSON.parse(blobString);
        } catch {
            throw new Error("Invalid transfer data");
        }
        // Throws "Incorrect password or corrupted data" on a wrong passphrase.
        const fullVault = await decryptVault(encrypted, transferPassphrase);
        // Reuse the validated clean-device import (re-encrypts under the new password).
        return this.importNewVault(JSON.stringify(fullVault), newLocalPassword);
    },

    // Merge accounts from a plaintext JSON export ({accounts:[...]}) or an
    // encrypted .kvault backup ({salt, iv, data}). `password` is the local vault
    // password (to decrypt/re-save this device's vault); `passphrase` is the
    // SEPARATE backup passphrase that decrypts a .kvault file — they are distinct
    // secrets and only one is the file's.
    async importVault(jsonString, password, passphrase) {
        if (this.isLocked) throw new Error("Vault locked");
        try {
            const parsed = JSON.parse(jsonString);

            // An encrypted .kvault backup carries no cleartext accounts; decrypt
            // it with its passphrase before merging. Older-format backups are
            // recognised too, so they get crypto-core's "older version" refusal
            // rather than "Invalid vault format".
            let data = parsed;
            if (isEncryptedVaultBlob(parsed)) {
                if (!passphrase) throw new Error("This is an encrypted .kvault backup — enter its passphrase");
                data = await decryptVault(parsed, passphrase);
            }

            if (!data.accounts || !Array.isArray(data.accounts)) throw new Error("Invalid vault format");

            // 1. Get Full Vault
            const fullVault = await this._getFullVault(password);

            let addedCount = 0;
            for (const rawAcc of data.accounts) {
                // Re-derived from its seeds, the id included: an account is
                // deduplicated by its ADDRESS, the same one whichever app
                // exported it (crypto-core 4.0.0).
                const acc = parseAccount(rawAcc);

                const existingIndex = fullVault.accounts.findIndex(existing => existing.id === acc.id);
                if (existingIndex >= 0) {
                    fullVault.accounts[existingIndex] = acc;
                } else {
                    fullVault.accounts.push(acc);
                }
                addedCount++;
            }

            if (addedCount > 0) {
                await this._save(fullVault, password);
                importTrustStores(data.trustStore); // merged, local pins win

                // Re-sync memory completely to ensure consistency
                this.vault = {
                    accounts: fullVault.accounts.map(acc => this._sanitize(acc)),
                    activeAccountId: fullVault.activeAccountId
                };
            }
            return addedCount;
        } catch (e) {
            throw new Error("Import failed: " + e.message);
        }
    },
};
