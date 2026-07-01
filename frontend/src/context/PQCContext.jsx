import { createContext, useContext, useState, useEffect } from 'react';
import API_ENDPOINTS from '../config';
import { useAuth } from './AuthContext';
import { vaultService } from '../services/vault';
import { domainSeparate, SIGNING_CONTEXT } from '../utils/crypto';
import { toast } from '../utils/toast';

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
            } catch {
                // auto-biometrics cancelled/unsupported — fall back to manual prompt
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

    const performServerLogin = async (accountId, encryptionKey, signFn, username = null, inviteCode = null) => {
        // 1. Get Nonce
        const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(accountId));
        if (!nonceRes.ok) throw new Error("Failed to fetch nonce");
        const { nonce } = await nonceRes.json();

        // 2. Sign Nonce — bind the encryption (ML-KEM) key into the challenge so
        //    the identity's signature authorizes it (M-2). The challenge is
        //    domain-separated under the `login` context (H1) so a content-signing
        //    operation can never produce these bytes. Must match the server.
        const body = `Sign in to Kryptolog with nonce: ${nonce}` +
            (encryptionKey ? `\nEncryption key: ${encryptionKey}` : '');
        const message = domainSeparate(SIGNING_CONTEXT.LOGIN, body);
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
                username: username, // Send preferred username
                // Only meaningful on first-login (server ignores it for existing
                // identities). Collected on the create/import screens (audit §5).
                invite_code: inviteCode || undefined
            })
        });

        if (loginRes.ok) {
            const data = await loginRes.json();
            authLogin(data.user, 'trustkeys', data.access_token);
            return data.user;
        } else {
            const errData = await loginRes.json().catch(() => null);
            const detail = errData?.detail || `Login failed (${loginRes.status})`;
            const err = new Error(detail);
            // 403 from /auth/login means a new identity needs an invite code
            // (audit §5) — tag it so the UI can prompt for one and retry.
            if (loginRes.status === 403) err.code = 'INVITE_REQUIRED';
            throw err;
        }
    };

    const loginTrustKeys = async (inviteCode = null) => {
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

        // inviteCode is only consulted server-side when this is a new identity and
        // invites are required (audit §5); harmless otherwise.
        return performServerLogin(accountId, encryptionKey, (msg) => window.trustkeys.sign(msg), tkAccount.name, inviteCode);
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

    const createLocalVault = async (name, password, inviteCode = null) => {
        const account = await vaultService.setup(name, password);
        const accountId = account.dilithium.publicKey;
        const encryptionKey = account.kyber.publicKey;

        setHasLocalVault(true);

        setPqcAccount(accountId);
        setKyberKey(encryptionKey);

        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, password), name, inviteCode);
    };

    const importLocalVault = async (json, password, inviteCode = null) => {
        // Create a new local vault from an exported backup, then log in with it.
        const account = await vaultService.importNewVault(json, password);
        const accountId = account.dilithium.publicKey;
        const encryptionKey = account.kyber.publicKey;

        setHasLocalVault(true);
        setPqcAccount(accountId);
        setKyberKey(encryptionKey);

        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, password), account.name, inviteCode);
    };

    // --- Device-to-device transfer ---
    // Read the full vault (prompts for password / uses cache) and return an
    // encrypted blob under `transferPassphrase`. Backs both the encrypted-backup
    // file and the server relay; the passphrase never goes to the server.
    const exportEncryptedVault = async (transferPassphrase) => {
        const password = await requestPassword("Enter your vault password to export:");
        return vaultService.exportEncryptedBlob(transferPassphrase, password);
    };

    // Clean-device receive: decrypt the transferred blob with the passphrase,
    // create a local vault under a NEW device password, then log in.
    const receiveVault = async (blobString, transferPassphrase, newLocalPassword, inviteCode = null) => {
        const account = await vaultService.importEncryptedBlob(blobString, transferPassphrase, newLocalPassword);
        const accountId = account.dilithium.publicKey;
        const encryptionKey = account.kyber.publicKey;

        setHasLocalVault(true);
        setPqcAccount(accountId);
        setKyberKey(encryptionKey);

        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, newLocalPassword), account.name, inviteCode);
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
            // Fallback: use the in-process library when a target key is supplied
            // (e.g. encrypting for a contact before the local vault is unlocked).
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

    // Sign a chat message (audit S1). Distinct from sign() so it can stay SILENT
    // per message: the extension auto-signs message-domain payloads, and the
    // local vault caches the signing key after a single unlock this session.
    const signMessage = async (body) => {
        if (isExtensionAvailable && window.trustkeys) {
            // Older extensions without the silent path fall back to sign() (pops a
            // popup per message, but stays functional).
            if (window.trustkeys.signMessage) {
                return await window.trustkeys.signMessage(body);
            }
            return await window.trustkeys.sign(body);
        } else if (!vaultService.isLocked) {
            if (vaultService.hasCachedSigningKey()) {
                return await vaultService.signMessage(body);
            }
            const password = await requestPassword("Enter password to enable secure messaging:");
            return await vaultService.signMessage(body, password);
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

    const importVault = async (json, passphrase) => {
        const password = await requestPassword("Enter password to IMPORT vault:");
        return vaultService.importVault(json, password, passphrase);
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
            toast.error("Biometric authentication failed: " + e.message);
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
            importLocalVault,
            encrypt,
            decrypt,
            decryptMany,
            sign,
            signMessage,
            getVaultAccounts,
            addVaultAccount,
            switchVaultAccount,
            deleteVaultAccount,
            exportVault,
            importVault,
            exportEncryptedVault,
            receiveVault,
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

                // performServerLogin needs a signing function, and vaultService.sign
                // requires the vault password. Recover it via the same biometric
                // unlock so we can sign the login challenge without prompting again.
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
