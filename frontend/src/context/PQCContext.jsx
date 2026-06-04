import React, { createContext, useContext, useState, useEffect } from 'react';
import API_ENDPOINTS from '../config';
import { useAuth } from './AuthContext';
import { vaultService } from '../services/vault';

const PQCContext = createContext();

export const usePQC = () => {
    const context = useContext(PQCContext);
    if (!context) {
        throw new Error('usePQC must be used within a PQCProvider');
    }
    return context;
};

import PasswordModal from '../components/PasswordModal';

export const PQCProvider = ({ children }) => {
    const { login: authLogin, logout: authLogout } = useAuth();
    const [pqcAccount, setPqcAccount] = useState(null); // Dilithium Public Key
    const [kyberKey, setKyberKey] = useState(null);
    const [isExtensionAvailable, setIsExtensionAvailable] = useState(false);
    const [hasLocalVault, setHasLocalVault] = useState(false);

    // Modal State
    const [modalConfig, setModalConfig] = useState({
        isOpen: false,
        message: '',
        resolve: null,
        reject: null
    });

    const [biometricsEnabled, setBiometricsEnabled] = useState(false);

    useEffect(() => {
        // Check availability on mount and slightly after (for injection delay)
        const check = () => {
            setIsExtensionAvailable(!!window.trustkeys);
            setHasLocalVault(vaultService.hasVault());
            setBiometricsEnabled(vaultService.hasBiometrics());
        };
        check();
        const t = setTimeout(check, 500);
        return () => clearTimeout(t);
    }, []);

    // FIX: Clear state if authType changes away from trustkeys (Logout or Switch)
    const { authType } = useAuth();
    useEffect(() => {
        if (authType !== 'trustkeys') {
            setPqcAccount(null);
            setKyberKey(null);
            vaultService.clearKeyCache();
        }
    }, [authType]);

    // Clear derived key cache when tab/app is hidden (security hardening)
    useEffect(() => {
        const handleVisibilityChange = () => {
            if (document.hidden) vaultService.clearKeyCache();
        };
        document.addEventListener('visibilitychange', handleVisibilityChange);
        return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
    }, []);

    // Internal helper to request password via Modal
    const requestPassword = async (message = "Please enter your vault password to continue.") => {
        // Derived key cache — skip prompt entirely if cache is still valid
        if (vaultService.hasCachedKey()) {
            return null; // vault methods will use the cached key
        }

        // Auto-Biometrics
        if (biometricsEnabled) {
            try {
                const password = await vaultService.recoverPasswordWithBiometrics();
                return password;
            } catch (e) {
                console.log("Auto-biometrics failed/cancelled, falling back to manual:", e);
            }
        }

        return new Promise((resolve, reject) => {
            setModalConfig({
                isOpen: true,
                message,
                resolve,
                reject
            });
        });
    };

    const handleModalSubmit = (password) => {
        if (modalConfig.resolve) {
            modalConfig.resolve(password);
        }
        setModalConfig({ ...modalConfig, isOpen: false, resolve: null, reject: null });
    };

    const handleModalCancel = () => {
        if (modalConfig.reject) {
            modalConfig.reject(new Error("User cancelled password prompt"));
        }
        setModalConfig({ ...modalConfig, isOpen: false, resolve: null, reject: null });
    };

    const performServerLogin = async (accountId, encryptionKey, signFn, username = null) => {
        // 1. Get Nonce
        const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(accountId));
        if (!nonceRes.ok) throw new Error("Failed to fetch nonce");
        const { nonce } = await nonceRes.json();

        // 2. Sign Nonce
        const message = `Sign in to Kryptolog with nonce: ${nonce}`;
        const signature = await signFn(message);

        // 3. Verify on Backend
        const loginRes = await fetch(API_ENDPOINTS.AUTH.LOGIN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address: accountId,
                signature,
                nonce,
                encryption_public_key: encryptionKey,
                username: username // Send preferred username
            })
        });

        if (loginRes.ok) {
            const data = await loginRes.json();
            authLogin(data.user, 'trustkeys', data.access_token);
            return data.user;
        } else {
            const errData = await loginRes.json().catch(() => null);
            const detail = errData?.detail || `Login failed (${loginRes.status})`;
            throw new Error(detail);
        }
    };

    const loginTrustKeys = async () => {
        if (!window.trustkeys) {
            throw new Error("Extension not found");
        }

        const connected = await window.trustkeys.connect();
        if (!connected) throw new Error("Connection request rejected.");

        if (window.trustkeys.handshake) {
            await window.trustkeys.handshake();
        }

        const tkAccount = await window.trustkeys.getAccount();
        const accountId = tkAccount.dilithiumPublicKey;
        const encryptionKey = tkAccount.kyberPublicKey;

        setPqcAccount(accountId);
        setKyberKey(encryptionKey);

        return performServerLogin(accountId, encryptionKey, (msg) => window.trustkeys.sign(msg), tkAccount.name);
    };

    const loginLocalVault = async (password) => {
        const success = await vaultService.unlock(password);
        if (!success) throw new Error("Incorrect password");

        const account = vaultService.getActiveAccount();
        const accountId = account.dilithium.publicKey;
        const encryptionKey = account.kyber.publicKey;

        setPqcAccount(accountId);
        setKyberKey(encryptionKey);

        // Pass known password
        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, password), account.name);
    };

    const createLocalVault = async (name, password) => {
        const account = await vaultService.setup(name, password);
        const accountId = account.dilithium.publicKey;
        const encryptionKey = account.kyber.publicKey;

        setHasLocalVault(true);

        setPqcAccount(accountId);
        setKyberKey(encryptionKey);

        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, password), name);
    };

    const generateSessionKey = async () => {
        if (isExtensionAvailable && window.trustkeys) {
            return await window.trustkeys.generateSessionKey();
        } else if (!vaultService.isLocked) {
            return await vaultService.generateSessionKey();
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const wrapSessionKey = async (sessionKey, publicKey) => {
        if (isExtensionAvailable && window.trustkeys) {
            return await window.trustkeys.wrapSessionKey(sessionKey, publicKey);
        } else if (!vaultService.isLocked) {
            return await vaultService.wrapSessionKey(sessionKey, publicKey);
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const unwrapSessionKey = async (wrappedKey) => {
        if (isExtensionAvailable && window.trustkeys) {
            return await window.trustkeys.unwrapSessionKey(wrappedKey);
        } else if (!vaultService.isLocked) {
            const password = await requestPassword("Enter password to unwrap session key:");
            return await vaultService.unwrapSessionKey(wrappedKey, password);
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const unwrapManySessionKeys = async (wrappedKeys) => {
        if (isExtensionAvailable && window.trustkeys) {
            if (window.trustkeys.unwrapManySessionKeys) {
                return await window.trustkeys.unwrapManySessionKeys(wrappedKeys);
            }
            // Fallback for older extension versions
            return await Promise.all(wrappedKeys.map(wk => window.trustkeys.unwrapSessionKey(wk)));
        } else if (!vaultService.isLocked) {
            // Local Vault: ONE prompt
            const password = await requestPassword("Enter password to unlock session keys (Batch):");
            return await vaultService.unwrapManySessionKeys(wrappedKeys, password);
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const encrypt = async (content, publicKey) => {
        if (isExtensionAvailable && window.trustkeys) {
            return await window.trustkeys.encrypt(content, publicKey || kyberKey);
        } else {
            // Fallback: Use internal library if we have a key
            // This allows MetaMask users to encrypt for PQC users without vault
            if (!publicKey && vaultService.isLocked) {
                // If no public key provided AND vault locked (no kyberKey), we can't encrypt
                throw new Error("PQC Provider not ready (Locked or Missing)");
            }

            const targetKey = publicKey || kyberKey;
            if (!targetKey) throw new Error("No encryption key available");

            const { encryptMessagePQC } = await import('../utils/crypto');
            return await encryptMessagePQC(content, targetKey);
        }
    };

    const sign = async (message) => {
        if (isExtensionAvailable && window.trustkeys) {
            return await window.trustkeys.sign(message);
        } else if (!vaultService.isLocked) {
            const password = await requestPassword("Enter password to sign document:");
            return await vaultService.sign(message, password);
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const decrypt = async (encryptedObject) => {
        if (isExtensionAvailable && window.trustkeys) {
            return await window.trustkeys.decrypt(encryptedObject);
        } else if (!vaultService.isLocked) {
            const password = await requestPassword("Enter password to decrypt data:");
            return await vaultService.decrypt(encryptedObject, password);
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const decryptMany = async (encryptedObjects) => {
        if (isExtensionAvailable && window.trustkeys) {
            // Extension sequential fallback (or assume potential future batch support)
            const results = [];
            for (const obj of encryptedObjects) {
                try {
                    results.push(await window.trustkeys.decrypt(obj));
                } catch (e) {
                    console.error("Decrypt Error", e);
                    results.push("Error: Decryption Failed");
                }
            }
            return results;
        } else if (!vaultService.isLocked) {
            const password = await requestPassword(`Enter password to decrypt ${encryptedObjects.length} messages:`);
            return await vaultService.decryptMany(encryptedObjects, password);
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const getVaultAccounts = () => vaultService.getAccounts();

    const addVaultAccount = async (name) => {
        const password = await requestPassword("Enter password to create new account:");
        const acc = await vaultService.addAccount(name, password);
        return acc;
    };

    const switchVaultAccount = async (id) => {
        const password = await requestPassword("Enter password to switch account:");
        const account = await vaultService.switchAccount(id, password);

        const accountId = account.dilithium.publicKey;
        const encryptionKey = account.kyber.publicKey;

        setPqcAccount(accountId);
        setKyberKey(encryptionKey);

        authLogout();
        // explicit logout forces user to re-login with new identity attempt


        return account;
    };

    const deleteVaultAccount = async (id) => {
        const password = await requestPassword("Enter password to DELETE account:");
        await vaultService.deleteAccount(id, password);

        const current = vaultService.getActiveAccount();
        if (current) {
            setPqcAccount(current.dilithium.publicKey);
            setKyberKey(current.kyber.publicKey);
        }
    };

    const exportVault = async () => {
        const password = await requestPassword("Enter password to EXPORT vault:");
        return vaultService.exportVault(password);
    };

    const importVault = async (json) => {
        const password = await requestPassword("Enter password to IMPORT vault:");
        return vaultService.importVault(json, password);
    };

    const handleBiometricAuth = async () => {
        try {
            const password = await vaultService.recoverPasswordWithBiometrics();
            if (modalConfig.resolve) {
                modalConfig.resolve(password);
            }
            setModalConfig({ ...modalConfig, isOpen: false, resolve: null, reject: null });
        } catch (e) {
            console.error("Biometric auth failed", e);
            alert("Biometric authentication failed: " + e.message);
        }
    };

    return (
        <PQCContext.Provider value={{
            pqcAccount,
            kyberKey,
            isExtensionAvailable,
            hasLocalVault,
            loginTrustKeys,
            loginLocalVault,
            createLocalVault,
            encrypt,
            decrypt,
            decryptMany,
            sign,
            getVaultAccounts,
            addVaultAccount,
            switchVaultAccount,
            deleteVaultAccount,
            exportVault,
            importVault,
            generateSessionKey,
            wrapSessionKey,
            unwrapSessionKey,
            unwrapManySessionKeys,
            // Biometrics
            manageBiometrics: async (enable) => {
                if (enable) {
                    const password = await requestPassword("Enter password to ENABLE FaceID/TouchID:");
                    const mode = await vaultService.enableBiometrics(password);
                    setBiometricsEnabled(true);
                    return mode; // always 'prf' (enableBiometrics throws on unsupported devices)
                } else {
                    vaultService.disableBiometrics();
                    setBiometricsEnabled(false);
                }
            },
            unlockWithBiometrics: async () => {
                const success = await vaultService.unlockWithBiometrics();
                if (!success) throw new Error("Biometric Unlock Failed");

                const account = vaultService.getActiveAccount();
                const accountId = account.dilithium.publicKey;
                const encryptionKey = account.kyber.publicKey;

                setPqcAccount(accountId);
                setKyberKey(encryptionKey);

                // Perform login sequence if needed, or just set local state?
                // Depending on usage, we might want to trigger server login too?
                // For now, mirroring loginLocalVault but without password arg for signing?
                // Wait, performServerLogin NEEDS a signing function.
                // If we unlock with biometrics, we have the PRIVATE KEY in memory now.
                // So we can sign!

                // We need the password to sign? 
                // performServerLogin takes a signFn.
                // vaultService.sign(msg, password) -> NEEDS PASSWORD
                // If we just unlocked, we don't have the password stored!
                // We need to pass the password to signFn.

                // FIX: unlockWithBiometrics in vault.js uses recoverPasswordWithBiometrics internally
                // but usually discards it.
                // We should probably get it here to pass to signFn.

                const password = await vaultService.recoverPasswordWithBiometrics();

                return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, password), account.name);
            },
            hasBiometrics: () => biometricsEnabled
        }}>
            {children}

            <PasswordModal
                isOpen={modalConfig.isOpen}
                message={modalConfig.message}
                onSubmit={handleModalSubmit}
                onCancel={handleModalCancel}
                onBiometric={biometricsEnabled ? handleBiometricAuth : null}
            />
        </PQCContext.Provider>
    );
};
