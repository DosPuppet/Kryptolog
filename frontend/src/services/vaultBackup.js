import { encryptVault, decryptVault, normalizeAccount } from '../utils/crypto';

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
        if (!password || password.length < 6) {
            throw new Error("Password must be at least 6 characters");
        }

        let data;
        try {
            data = JSON.parse(jsonString);
        } catch {
            throw new Error("Invalid file: not valid JSON");
        }
        if (!data.accounts || !Array.isArray(data.accounts) || data.accounts.length === 0) {
            throw new Error("Invalid vault file: no accounts found");
        }
        // Accept both the current (mlkem/mldsa) and legacy (kyber/dilithium)
        // field names from exported backups, then normalize to the new shape.
        const accounts = data.accounts.map(normalizeAccount);
        for (const acc of accounts) {
            if (!acc?.mldsa?.publicKey || !acc?.mldsa?.privateKey ||
                !acc?.mlkem?.publicKey || !acc?.mlkem?.privateKey) {
                throw new Error("Invalid vault file: accounts are missing key material");
            }
            // Normalize id to the ML-DSA public key (matches setup/import conventions).
            acc.id = acc.mldsa.publicKey;
        }

        const activeAccountId = (data.activeAccountId &&
            accounts.some(a => a.id === data.activeAccountId))
            ? data.activeAccountId
            : accounts[0].id;

        const fullVault = { accounts, activeAccountId };

        // Encrypt + persist under the new password, then expose sanitized in memory.
        await this._save(fullVault, password);
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
        // Export plaintext (sensitive!)
        return JSON.stringify(fullVault, null, 2);
    },

    // --- Device-to-device transfer ---
    // Produce an ENCRYPTED vault blob (the full vault, AES-GCM under a one-time
    // transfer passphrase). Used for both the downloadable encrypted-backup file
    // and the server relay — the passphrase is carried out of band, never sent
    // to the server. `vaultPassword` may be null when a derived key is cached.
    async exportEncryptedBlob(transferPassphrase, vaultPassword) {
        if (this.isLocked) throw new Error("Vault locked");
        if (!transferPassphrase) throw new Error("Transfer passphrase required");
        const fullVault = await this._getFullVault(vaultPassword);
        const encrypted = await encryptVault(fullVault, transferPassphrase);
        return JSON.stringify(encrypted);
    },

    // Consume an encrypted vault blob produced by exportEncryptedBlob on another
    // device: decrypt with the transfer passphrase, then re-encrypt locally under
    // a fresh device password. Clean-device flow (creates a new local vault).
    async importEncryptedBlob(blobString, transferPassphrase, newLocalPassword) {
        if (this.hasVault()) {
            throw new Error("A vault already exists on this device. Import from the Vault Manager while signed in.");
        }
        if (!newLocalPassword || newLocalPassword.length < 6) {
            throw new Error("Password must be at least 6 characters");
        }
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

            // An encrypted .kvault backup carries {salt, iv, data} and no cleartext
            // accounts; decrypt it with its passphrase before merging.
            let data = parsed;
            if (parsed && parsed.salt && parsed.iv && parsed.data && !parsed.accounts) {
                if (!passphrase) throw new Error("This is an encrypted .kvault backup — enter its passphrase");
                data = await decryptVault(parsed, passphrase);
            }

            if (!data.accounts || !Array.isArray(data.accounts)) throw new Error("Invalid vault format");

            // 1. Get Full Vault
            const fullVault = await this._getFullVault(password);

            let addedCount = 0;
            for (const rawAcc of data.accounts) {
                // Accept legacy kyber/dilithium backups, then normalize.
                const acc = normalizeAccount(rawAcc);
                // FORCE ID normalization
                if (acc.mldsa && acc.mldsa.publicKey) {
                    acc.id = acc.mldsa.publicKey;
                }

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
