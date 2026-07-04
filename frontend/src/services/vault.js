import { encryptVault, decryptVaultWithKey, encryptVaultWithKey, deriveKey, fromHex, generateAccount, signMessagePQC, decryptMessagePQC, unwrapSessionKey, generateSessionKey, wrapSessionKey, normalizeAccount } from '../utils/crypto';
import { backupMethods } from './vaultBackup';
import { biometricMethods } from './vaultBiometrics';

// Core key-custody service: encrypted-vault storage, derived-key session cache,
// lock/unlock, account CRUD, and the on-demand private-key operations.
// Backup/transfer (vaultBackup.js) and biometric unlock (vaultBiometrics.js)
// methods are merged onto the prototype below — one singleton, one API.
class VaultService {
    constructor() {
        this.vault = null; // Will ONLY contain sanitized accounts (No Private Keys)
        this.isLocked = true;
        // NO currentPassword stored here!

        // --- Derived key session cache ---
        this._cachedKey = null;      // CryptoKey (non-extractable AES-GCM 256)
        this._cachedSalt = null;     // Uint8Array(16) — salt used to derive _cachedKey
        this._cacheTimer = null;     // setTimeout reference for auto-expiry
        this._signingKey = null;     // active account ML-DSA private key (message signing, audit S1)
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
        // Also drop the in-memory message-signing key (audit S1): cleared on
        // lock / tab-hide just like the derived vault key.
        this._signingKey = null;
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
            mldsa: {
                publicKey: account.mldsa.publicKey
                // privateKey is REMOVED
            },
            mlkem: {
                publicKey: account.mlkem.publicKey
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
                return this._normalizeVault(vault);
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
        return this._normalizeVault(vault);
    }

    // Map legacy kyber/dilithium account fields to mlkem/mldsa on load (compat,
    // crypto-core v1.2.0). Applied wherever a vault is decrypted from storage or
    // an import, so all downstream code sees only the current field names; the
    // next _save() then re-persists the normalized shape.
    _normalizeVault(vault) {
        if (vault && Array.isArray(vault.accounts)) {
            vault.accounts = vault.accounts.map(normalizeAccount);
        }
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

    async unlock(password) {
        const encryptedJson = localStorage.getItem('kryptolog_vault');
        if (!encryptedJson) throw new Error("No vault found");

        try {
            const encrypted = JSON.parse(encryptedJson);

            // 1. Derive key explicitly so we can cache it
            const salt = fromHex(encrypted.salt);
            const key = await deriveKey(password, salt);

            // 2. Decrypt with derived key (normalize legacy field names on load)
            const fullVault = this._normalizeVault(await decryptVaultWithKey(encrypted, key));

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
        this._signingKey = null;
        this.clearKeyCache();
    }

    // --- Message signing (audit S1) ---
    // Whether the active account's signing key is cached for silent message
    // signing (primed once per messenger session, cleared on lock/tab-hide).
    hasCachedSigningKey() {
        return !!this._signingKey;
    }

    // Sign one chat message. The first call this session derives and caches the
    // active account's ML-DSA private key (needs `password` or a cached vault
    // key); subsequent calls sign silently. Kept separate from the per-op
    // `sign()` so messaging doesn't prompt on every message.
    async signMessage(body, password = null) {
        if (this.isLocked) throw new Error("Vault locked");
        if (!this._signingKey) {
            const fullVault = await this._getFullVault(password);
            const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);
            if (!account) throw new Error("Active account not found in vault");
            this._signingKey = account.mldsa.privateKey;
        }
        return signMessagePQC(body, this._signingKey);
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
            mldsaPublicKey: a.mldsa.publicKey,
            mlkemPublicKey: a.mlkem.publicKey
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

    async sign(message, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. DECRYPT ON DEMAND
        const fullVault = await this._getFullVault(password);
        const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);

        if (!account) throw new Error("Active account not found in vault");

        // 2. USE KEY
        const signature = await signMessagePQC(message, account.mldsa.privateKey);

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
        const plaintext = await decryptMessagePQC(encryptedData, account.mlkem.privateKey);

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
                return await decryptMessagePQC(item, account.mlkem.privateKey);
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
        return await unwrapSessionKey(wrappedKey, account.mlkem.privateKey);
    }

    async unwrapManySessionKeys(wrappedKeys, password) {
        if (this.isLocked) throw new Error("Vault locked");

        // 1. Load Vault to get Private Key (ONCE)
        const fullVault = await this._getFullVault(password);
        const account = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);
        if (!account) throw new Error("Active account not found");

        const privKey = account.mlkem.privateKey;

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
}

Object.assign(VaultService.prototype, backupMethods, biometricMethods);

export const vaultService = new VaultService();
