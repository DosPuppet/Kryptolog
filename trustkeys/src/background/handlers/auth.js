import {
    deriveVaultKeyBits, importVaultKey, decryptVaultWithKey, normalizeAccount, vaultKdfOf,
    vaultPasswordProblem,
} from '../../utils/crypto.js';
import { state } from '../state.js';
import { saveVault } from '../utils.js';
import { persistSession, clearSession, readSession } from '../session.js';

export const setupPassword = async (password) => {
    if (state.hasPassword) throw new Error("Password already set");
    // Enforced here, where the vault is sealed, not only in the popup form:
    // the floor was 4 characters (audit 2026-10-12 K-08, 2026-09-11 M-5).
    const problem = vaultPasswordProblem(password);
    if (problem) throw new Error(problem);

    state.vault = { accounts: [], activeAccountId: null, permissions: {}, autoSignSites: {} };
    await saveVault(password);
    state.isLocked = false;
    return true;
};

/**
 * Install the decrypted vault as the unlocked session. Shared by the password
 * path and the session-restore path so "unlocked" means one thing.
 */
const openVault = async (vaultData, keyBytes, kdf) => {
    const key = await importVaultKey(keyBytes);
    const vault = await decryptVaultWithKey(vaultData, key); // throws on a wrong key

    // Migration: map legacy kyber/dilithium account fields to mlkem/mldsa
    // (compat, crypto-core v1.2.0) so older vaults keep opening.
    if (Array.isArray(vault.accounts)) {
        vault.accounts = vault.accounts.map(normalizeAccount);
    }
    // Migration: Ensure permissions + per-site capability objects exist
    if (!vault.permissions) vault.permissions = {};
    if (!vault.autoSignSites) vault.autoSignSites = {};

    state.vault = vault;
    state.vaultKey = key;
    state.vaultKeyBytes = keyBytes;
    state.vaultKdf = kdf;
    state.isLocked = false;
    return true;
};

export const unlock = async (password) => {
    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) throw new Error("No vault found");

    try {
        // Derive ONCE here and cache the key for the session, so every later
        // save reuses it instead of re-running the deliberately slow Argon2id
        // KDF. The raw bytes are kept alongside the CryptoKey because only
        // they can survive a service-worker restart (audit M-4).
        // Parameters from the blob itself (crypto-core 3.0.0).
        const kdf = vaultKdfOf(vaultData);
        const keyBytes = await deriveVaultKeyBits(password, kdf);
        return await openVault(vaultData, keyBytes, kdf);
    } catch (e) {
        console.error("Unlock failed", e);
        return false;
    }
};

export const lock = () => {
    state.vault = null;
    state.isLocked = true;
    state.vaultKey = null;
    state.vaultKeyBytes = null;
    state.vaultKdf = null;
};

export const unlockWithSession = async (password) => {
    const success = await unlock(password);
    if (success) await persistSession();
    return success;
};

/**
 * Resume an unlocked session after a service-worker restart, from the cached key
 * bytes rather than a stored password (audit M-4). Also skips the KDF entirely,
 * so a restart is instant instead of a fresh Argon2id derivation.
 */
export const restoreSession = async () => {
    const session = await readSession();
    if (!session) return false;

    const { vaultData } = await chrome.storage.local.get('vaultData');
    if (!vaultData) return false;

    try {
        return await openVault(vaultData, session.keyBytes, session.kdf);
    } catch (e) {
        // Stale key (the vault was re-saved under a new salt elsewhere) — drop
        // it rather than leaving material around that no longer opens anything.
        console.warn("Session restore failed", e);
        await clearSession();
        return false;
    }
};

export const lockWithSession = async () => {
    lock();
    await clearSession();
};
