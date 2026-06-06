import { encryptVault, encryptVaultWithKey, decryptVaultWithKey, deriveKey, fromHex, generateAccount, signMessagePQC, decryptMessagePQC, unwrapSessionKey, generateSessionKey, wrapSessionKey } from '../utils/crypto';

class VaultService {
    constructor() {
        this.vault = null; // Will ONLY contain sanitized accounts (No Private Keys)
        this.isLocked = true;
        // NO currentPassword stored here!

        // --- Derived key session cache ---
        this._cachedKey = null;      // CryptoKey (non-extractable AES-GCM 256)
        this._cachedSalt = null;     // Uint8Array(16) — salt used to derive _cachedKey
        this._cacheTimer = null;     // setTimeout reference for auto-expiry
        const savedTTL = parseInt(localStorage.getItem('kryptolog_key_cache_ttl') || '0', 10);
        this._cacheTTL = isNaN(savedTTL) ? 0 : savedTTL; // 0 = "always ask" (default)
    }

    // --- Key Cache Methods ---

    setCacheTTL(ms) {
        this._cacheTTL = ms;
        localStorage.setItem('kryptolog_key_cache_ttl', String(ms));
        if (ms === 0) this.clearKeyCache();
    }

    getCacheTTL() {
        return this._cacheTTL;
    }

    hasCachedKey() {
        if (!this._cachedKey || !this._cachedSalt) return false;
        return true;
    }

    clearKeyCache() {
        this._cachedKey = null;
        this._cachedSalt = null;
        if (this._cacheTimer) {
            clearTimeout(this._cacheTimer);
            this._cacheTimer = null;
        }
    }

    _cacheKey(key, salt) {
        if (this._cacheTTL === 0) return; // "always ask" — no caching
        this._cachedKey = key;
        this._cachedSalt = salt;
        this._touchCache();
    }

    _touchCache() {
        if (this._cacheTTL === 0 || !this._cachedKey) return;
        if (this._cacheTimer) clearTimeout(this._cacheTimer);
        this._cacheTimer = setTimeout(() => this.clearKeyCache(), this._cacheTTL);
    }

    // --- Core Helpers ---

    hasVault() {
        return !!localStorage.getItem('kryptolog_vault');
    }

    // Helper to sanitize an account (remove private keys)
    _sanitize(account) {
        return {
            ...account,
            dilithium: {
                publicKey: account.dilithium.publicKey
                // privateKey is REMOVED
            },
            kyber: {
                publicKey: account.kyber.publicKey
                // privateKey is REMOVED
            }
        };
    }

    // Helper to get the FULL vault (decrypted) temporarily
    // ONLY used within this class for specific operations
    // password can be null when a cached key is available
    async _getFullVault(password) {
        const encryptedJson = localStorage.getItem('kryptolog_vault');
        if (!encryptedJson) throw new Error("No vault found");
        const encrypted = JSON.parse(encryptedJson);

        // Try cached key first
        if (this.hasCachedKey()) {
            try {
                const vault = await decryptVaultWithKey(encrypted, this._cachedKey);
                this._touchCache();
                return vault;
            } catch {
                this.clearKeyCache(); // stale cache — fall through to password
            }
        }

        // Fall back to password-based derivation
        if (!password) throw new Error("Password required");
        const salt = fromHex(encrypted.salt);
        const key = await deriveKey(password, salt);
        const vault = await decryptVaultWithKey(encrypted, key);
        this._cacheKey(key, salt);
        return vault;
    }

    // Internal helper to save a FULL vault
    // password can be null when a cached key is available
    async _save(fullVault, password) {
        let encrypted;

        if (this.hasCachedKey()) {
            encrypted = await encryptVaultWithKey(fullVault, this._cachedKey, this._cachedSalt);
            this._touchCache();
        } else {
            if (!password) throw new Error("Password required to save");
            encrypted = await encryptVault(fullVault, password);
            // Cache the new key from the freshly encrypted vault
            const salt = fromHex(encrypted.salt);
            const key = await deriveKey(password, salt);
            this._cacheKey(key, salt);
        }

        localStorage.setItem('kryptolog_vault', JSON.stringify(encrypted));
    }

    // Public save is removed/disabled because we don't save the in-memory (sanitized) vault
    // Operations like add/delete handle saving internally via _save(fullVault)

    async setup(name, password) {
        if (this.hasVault()) throw new Error("Vault already exists");

        // 1. Generate full account with keys
        const account = await generateAccount(name);

        // 2. Create full vault
        const fullVault = {
            accounts: [account],
            activeAccountId: account.id
        };

        // 3. Encrypt and Save Full Vault
        await this._save(fullVault, password);

        // 4. Update Memory with SANITIZED vault
        this.vault = {
            accounts: [this._sanitize(account)],
            activeAccountId: account.id
        };
        this.isLocked = false;

        return this._sanitize(account);
    }

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
        for (const acc of data.accounts) {
            if (!acc?.dilithium?.publicKey || !acc?.dilithium?.privateKey ||
                !acc?.kyber?.publicKey || !acc?.kyber?.privateKey) {
                throw new Error("Invalid vault file: accounts are missing key material");
            }
            // Normalize id to the ML-DSA public key (matches setup/import conventions).
            acc.id = acc.dilithium.publicKey;
        }

        const activeAccountId = (data.activeAccountId &&
            data.accounts.some(a => a.id === data.activeAccountId))
            ? data.activeAccountId
            : data.accounts[0].id;

        const fullVault = { accounts: data.accounts, activeAccountId };

        // Encrypt + persist under the new password, then expose sanitized in memory.
        await this._save(fullVault, password);
        this.vault = {
            accounts: fullVault.accounts.map(acc => this._sanitize(acc)),
            activeAccountId
        };
        this.isLocked = false;

        const active = fullVault.accounts.find(a => a.id === activeAccountId);
        return this._sanitize(active);
    }

    async unlock(password) {
        const encryptedJson = localStorage.getItem('kryptolog_vault');
        if (!encryptedJson) throw new Error("No vault found");

        try {
            const encrypted = JSON.parse(encryptedJson);

            // 1. Derive key explicitly so we can cache it
            const salt = fromHex(encrypted.salt);
            const key = await deriveKey(password, salt);

            // 2. Decrypt with derived key
            const fullVault = await decryptVaultWithKey(encrypted, key);

            // 3. Cache the derived key
            this._cacheKey(key, salt);

            // 4. Sanitize for Memory
            this.vault = {
                accounts: fullVault.accounts.map(acc => this._sanitize(acc)),
                activeAccountId: fullVault.activeAccountId
            };

            this.isLocked = false;
            // Password is intentionally NOT saved
            return true;
        } catch (e) {
            console.error("Unlock failed", e);
            return false;
        }
    }

    lock() {
        this.vault = null;
        this.isLocked = true;
        this.clearKeyCache();
    }

    getActiveAccount() {
        if (this.isLocked || !this.vault) return null;
        // Returns SANITIZED account
        return this.vault.accounts.find(a => a.id === this.vault.activeAccountId);
    }

    getAccounts() {
        if (this.isLocked || !this.vault) return [];
        return this.vault.accounts.map(a => ({
            id: a.id,
            name: a.name,
            isActive: a.id === this.vault.activeAccountId,
            createdAt: a.createdAt,
            // Public keys are available if needed for UI, but no private keys
            dilithiumPublicKey: a.dilithium.publicKey,
            kyberPublicKey: a.kyber.publicKey
        }));
    }

    async addAccount(name, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. Decrypt full vault to modify it
        const fullVault = await this._getFullVault(password);

        // 2. Generate new account
        const account = await generateAccount(name);
        fullVault.accounts.push(account);

        // 3. Save full vault
        await this._save(fullVault, password);

        // 4. Update memory (sanitized)
        this.vault.accounts.push(this._sanitize(account));

        return this._sanitize(account);
    }

    async switchAccount(id, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. Load full vault
        const fullVault = await this._getFullVault(password);

        // 2. Validate ID
        const exists = fullVault.accounts.find(a => a.id === id);
        if (!exists) throw new Error("Account not found");

        // 3. Update Active ID
        fullVault.activeAccountId = id;

        // 4. Save
        await this._save(fullVault, password);

        // 5. Update Memory
        this.vault.activeAccountId = id;

        return this._sanitize(exists);
    }

    async deleteAccount(id, password) {
        if (this.isLocked) throw new Error("Vault locked");

        const fullVault = await this._getFullVault(password);

        if (fullVault.accounts.length <= 1) throw new Error("Cannot delete last account");

        if (fullVault.activeAccountId === id) {
            const other = fullVault.accounts.find(a => a.id !== id);
            fullVault.activeAccountId = other.id;
            this.vault.activeAccountId = other.id; // Sync memory
        }

        fullVault.accounts = fullVault.accounts.filter(a => a.id !== id);
        await this._save(fullVault, password);

        // Sync memory
        this.vault.accounts = this.vault.accounts.filter(a => a.id !== id);
    }

    async exportVault(password) {
        if (this.isLocked) throw new Error("Vault locked");
        const fullVault = await this._getFullVault(password);
        // Export plaintext (sensitive!)
        return JSON.stringify(fullVault, null, 2);
    }

    async importVault(jsonString, password) {
        if (this.isLocked) throw new Error("Vault locked");
        try {
            const data = JSON.parse(jsonString);
            if (!data.accounts || !Array.isArray(data.accounts)) throw new Error("Invalid vault format");

            // 1. Get Full Vault
            const fullVault = await this._getFullVault(password);

            let addedCount = 0;
            for (const acc of data.accounts) {
                // FORCE ID normalization
                if (acc.dilithium && acc.dilithium.publicKey) {
                    acc.id = acc.dilithium.publicKey;
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
    }

    async sign(message, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. DECRYPT ON DEMAND
        const fullVault = await this._getFullVault(password);
        const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);

        if (!account) throw new Error("Active account not found in vault");

        // 2. USE KEY
        const signature = await signMessagePQC(message, account.dilithium.privateKey);

        // 3. DISCARD (fullVault goes out of scope)
        return signature;
    }

    async decrypt(encryptedData, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. DECRYPT ON DEMAND
        const fullVault = await this._getFullVault(password);
        const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);

        if (!account) throw new Error("Active account not found in vault");

        // 2. USE KEY
        const plaintext = await decryptMessagePQC(encryptedData, account.kyber.privateKey);

        // 3. DISCARD
        return plaintext;
    }

    async decryptMany(encryptedItems, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. DECRYPT VAULT ONCE
        const fullVault = await this._getFullVault(password);
        const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);

        if (!account) throw new Error("Active account not found in vault");

        // 2. DECRYPT ALL MESSAGES
        // We catch errors per message so one failure doesn't break all
        return await Promise.all(encryptedItems.map(async (item) => {
            try {
                return await decryptMessagePQC(item, account.kyber.privateKey);
            } catch (e) {
                console.error("Failed to decrypt message:", e);
                return "Error: Decryption Failed";
            }
        }));
    }

    // --- Session Key Support ---

    async generateSessionKey() {
        // Stateless, but exposed for consistency
        return await generateSessionKey();
    }

    async wrapSessionKey(sessionKey, publicKey) {
        // Stateless, but exposed for consistency
        return await wrapSessionKey(sessionKey, publicKey);
    }

    async unwrapSessionKey(wrappedKey, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. Load Vault to get Private Key
        const fullVault = await this._getFullVault(password);
        const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);
        if (!account) throw new Error("Active account not found");

        // 2. Unwrap
        return await unwrapSessionKey(wrappedKey, account.kyber.privateKey);
    }

    async unwrapManySessionKeys(wrappedKeys, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. Load Vault to get Private Key (ONCE)
        const fullVault = await this._getFullVault(password);
        const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);
        if (!account) throw new Error("Active account not found");

        const privKey = account.kyber.privateKey;

        // 2. Unwrap All
        // We run these in parallel since we have the key
        return await Promise.all(wrappedKeys.map(async (blob) => {
            try {
                return await unwrapSessionKey(blob, privKey);
            } catch (e) {
                console.error("Batch unwrap item failed", e);
                return null;
            }
        }));
    }

    // --- Biometric Authentication (FaceID/TouchID) ---

    hasBiometrics() {
        const prefs = localStorage.getItem('kryptolog_biometrics');
        return !!prefs;
    }

    async enableBiometrics(password) {
        if (!window.PublicKeyCredential) throw new Error("Biometrics not supported on this device/browser.");

        // 1. Verify Password First
        const fullVault = await this._getFullVault(password); // will throw if wrong

        // 2. Register Credential (PRF or Fallback)
        const activeAcct = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);
        const name = activeAcct ? activeAcct.name : "Kryptolog User";

        const { registerBiometricCredential, encryptSymmetric, checkPrfSupport } = await import('../utils/crypto');

        if (!await checkPrfSupport()) {
            throw new Error("Your browser does not support WebAuthn. Biometrics unavailable.");
        }

        // Throws on devices without hardware-bound PRF — there is no software fallback.
        const result = await registerBiometricCredential(name);

        // 3. Encrypt the vault password with the hardware-bound PRF key
        const encryptedPass = await encryptSymmetric(password, result.prfKey);

        // Clear any key left by the removed legacy fallback path.
        localStorage.removeItem('kryptolog_bio_fallback_key');

        // 4. Save Preferences
        const prefs = {
            mode: 'prf',
            credentialId: result.credentialId,
            encryptedPass,
            prfSalt: result.prfSalt
        };
        localStorage.setItem('kryptolog_biometrics', JSON.stringify(prefs));

        return 'prf';
    }

    async recoverPasswordWithBiometrics() {
        if (!this.hasBiometrics()) throw new Error("Biometrics not set up.");

        const prefsString = localStorage.getItem('kryptolog_biometrics');
        if (!prefsString) throw new Error("No biometric preferences found.");
        const prefs = JSON.parse(prefsString);

        // 1. Authenticate & Get Key (passes mode so correct path is used)
        const { getBiometricKey, decryptSymmetric } = await import('../utils/crypto');

        const mode = prefs.mode || 'prf'; // backward compat: old prefs without mode default to prf
        const key = await getBiometricKey(prefs.credentialId, prefs.prfSalt, mode);

        // 2. Decrypt Password
        const password = await decryptSymmetric(prefs.encryptedPass, key);
        if (!password) throw new Error("Biometric decryption failed.");

        return password;
    }

    async unlockWithBiometrics() {
        const password = await this.recoverPasswordWithBiometrics();
        // 3. Unlock Vault
        return await this.unlock(password);
    }

    disableBiometrics() {
        localStorage.removeItem('kryptolog_biometrics');
        localStorage.removeItem('kryptolog_bio_fallback_key'); // Clean up fallback key if present
    }

    // Returns 'prf', 'fallback', or null if biometrics not enabled
    biometricMode() {
        const prefsString = localStorage.getItem('kryptolog_biometrics');
        if (!prefsString) return null;
        try {
            const prefs = JSON.parse(prefsString);
            return prefs.mode || 'prf'; // backward compat
        } catch {
            return null;
        }
    }
}

export const vaultService = new VaultService();
