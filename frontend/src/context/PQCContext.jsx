import { createContext, useContext, useState, useEffect, useRef } from 'react';
import API_ENDPOINTS from '../config';
import { useAuth } from './AuthContext';
import { vaultService } from '../services/vault';
import { loginChallengeBody, encryptionKeyAttestationBody, messageSigningBody, accountDeletionBody } from '../utils/crypto';
import { toast } from '../utils/toast';
import { apiFetch } from '../services/api';
import { fetchAllPages, pageUrl } from '../utils/paging';
import PasswordModal from '../components/PasswordModal';

const PQCContext = createContext();

export const usePQC = () => {
    const context = useContext(PQCContext);
    if (!context) {
        throw new Error('usePQC must be used within a PQCProvider');
    }
    return context;
};

export const PQCProvider = ({ children }) => {
    const { login: authLogin, logout: authLogout, token } = useAuth();
    const [pqcAccount, setPqcAccount] = useState(null); // ML-DSA public key
    const [mlkemKey, setMlkemKey] = useState(null);
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

    // Logging out or switching away from the extension must clear the cached
    // identity, or the next session starts holding the previous one's keys.
    const { authType } = useAuth();
    useEffect(() => {
        if (authType !== 'trustkeys') {
            setPqcAccount(null);
            setMlkemKey(null);
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

    // One outstanding password request at a time. `setModalConfig` holds a single
    // resolve/reject pair, so a second concurrent request overwrote the first's
    // and left that operation's promise hanging forever behind a spinner that
    // never resolved. The app issues custody calls in parallel on purpose
    // (hooks/useSecrets.js fetches own and shared secrets at once), so this is
    // the normal path, not an edge case — and one vault password answers them all.
    const passwordInFlight = useRef(null);

    // Internal helper to request password via Modal
    // `forcePrompt` is for the one caller that needs the PASSWORD itself rather
    // than the ability to use the vault: enabling biometrics wraps it, so both
    // shortcuts below would hand it something that is not the password — null
    // from the cache, or the old password from a registration being replaced.
    const requestPassword = async (message = "Please enter your vault password to continue.", { forcePrompt = false } = {}) => {
        // Derived key cache — skip prompt entirely if cache is still valid
        if (!forcePrompt && vaultService.hasCachedKey()) {
            return null; // vault methods will use the cached key
        }
        if (passwordInFlight.current) return passwordInFlight.current;

        const pending = (async () => {
            // Auto-Biometrics
            if (biometricsEnabled && !forcePrompt) {
                try {
                    return await vaultService.recoverPasswordWithBiometrics();
                } catch (e) {
                    // Falling back to the password box is right; doing it in
                    // silence is what made "biometric unlock works, then it asks
                    // for my password anyway" impossible to diagnose — the reason
                    // reached neither the user nor the console.
                    console.warn("Biometric unlock unavailable, asking for the password instead:", e);
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
        })().finally(() => {
            if (passwordInFlight.current === pending) passwordInFlight.current = null;
        });

        passwordInFlight.current = pending;
        return pending;
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

    const performServerLogin = async (accountId, encryptionKey, signFn, username = null, inviteCode = null, attestFn = null) => {
        // 1. Get Nonce
        const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(accountId));
        if (!nonceRes.ok) throw new Error("Failed to fetch nonce");
        const { nonce } = await nonceRes.json();

        // 2. Sign Nonce — bind the encryption (ML-KEM) key into the challenge so
        //    the identity's signature authorizes it (M-2). The challenge is
        //    domain-separated under the `login` context (H1) so a content-signing
        //    operation can never produce these bytes. Built by crypto-core, not
        //    spelled out here: this is the one string the server must agree with
        //    byte for byte, and a second copy of it cannot be kept honest.
        const message = loginChallengeBody(nonce, encryptionKey);
        const signature = await signFn(message);

        // 2b. Key attestation (audit M-1): self-sign our own ML-KEM key so peers
        //     can verify the directory's key binding against our address. Custody
        //     paths that can't produce one (older extension) proceed without —
        //     the account just shows as "unverified" to contacts.
        let attestation = null;
        if (encryptionKey) {
            try {
                attestation = attestFn
                    ? await attestFn()
                    : await signFn(encryptionKeyAttestationBody(encryptionKey));
            } catch (e) {
                console.warn("Key attestation unavailable, continuing without:", e);
            }
        }

        // 3. Verify on Backend
        const loginRes = await fetch(API_ENDPOINTS.AUTH.LOGIN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address: accountId,
                signature,
                nonce,
                encryption_public_key: encryptionKey,
                encryption_key_attestation: attestation || undefined,
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
            // 410 means this key was erased and can never register again. It
            // needs its own code precisely because it used to arrive as a 403
            // and inherited the branch above: the user was told to enter an
            // invite code for a key no code could ever admit.
            if (loginRes.status === 410) err.code = 'ACCOUNT_DELETED';
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
        // Accept the current field names, falling back to the legacy ones so a
        // newer SPA still works with an older installed TrustKeys build.
        const accountId = tkAccount.mldsaPublicKey || tkAccount.dilithiumPublicKey;
        const encryptionKey = tkAccount.mlkemPublicKey || tkAccount.kyberPublicKey;

        setPqcAccount(accountId);
        setMlkemKey(encryptionKey);

        // inviteCode is only consulted server-side when this is a new identity and
        // invites are required (audit §5); harmless otherwise.
        // Attestation comes from the dedicated popup-free extension API (it signs
        // a fixed, self-referential message — nothing site-controlled). An older
        // extension without it logs in fine, just without an attestation.
        const attestFn = window.trustkeys.getKeyAttestation
            ? () => window.trustkeys.getKeyAttestation()
            : () => null;
        return performServerLogin(accountId, encryptionKey, (msg) => window.trustkeys.sign(msg), tkAccount.name, inviteCode, attestFn);
    };

    // `inviteCode` is not dead weight on an unlock path: the vault is written to
    // localStorage by `setup()` *before* the server is asked anything, so a
    // create that the server refuses for want of an invite code (audit §5)
    // leaves a perfectly good local identity that the server has never seen.
    // Without this the only way back in was to clear localStorage by hand.
    const loginLocalVault = async (password, inviteCode = null) => {
        const success = await vaultService.unlock(password);
        if (!success) throw new Error("Incorrect password");

        const account = vaultService.getActiveAccount();
        const accountId = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setPqcAccount(accountId);
        setMlkemKey(encryptionKey);

        // Pass known password
        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, password), account.name, inviteCode);
    };

    const createLocalVault = async (name, password, inviteCode = null) => {
        const account = await vaultService.setup(name, password);
        const accountId = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setHasLocalVault(true);

        setPqcAccount(accountId);
        setMlkemKey(encryptionKey);

        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, password), name, inviteCode);
    };

    const importLocalVault = async (json, password, inviteCode = null) => {
        // Create a new local vault from an exported backup, then log in with it.
        const account = await vaultService.importNewVault(json, password);
        const accountId = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setHasLocalVault(true);
        setPqcAccount(accountId);
        setMlkemKey(encryptionKey);

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
        const accountId = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setHasLocalVault(true);
        setPqcAccount(accountId);
        setMlkemKey(encryptionKey);

        return performServerLogin(accountId, encryptionKey, (msg) => vaultService.sign(msg, newLocalPassword), account.name, inviteCode);
    };

    // Every custody operation answers the same question first: is the key held
    // by the extension, or by an unlocked local vault, or is neither available?
    // That was nine copies of one if/else-if/throw, including nine copies of the
    // error string, which is the sort of thing that ends up saying two different
    // things after a rename.
    //
    // `prompt` is the password prompt the local-vault path needs; the extension
    // never takes one, because it holds the key itself and shows its own
    // approval window. Omit it for operations the vault can do without
    // unlocking a private key, or pass a function to decide per call — chat
    // message signing skips the prompt once the signing key is cached.
    const withCustody = (viaExtension, viaVault, prompt) => async (...args) => {
        if (isExtensionAvailable && window.trustkeys) {
            return viaExtension(...args);
        }
        if (!vaultService.isLocked) {
            const ask = typeof prompt === 'function' ? prompt(...args) : prompt;
            const password = ask ? await requestPassword(ask) : undefined;
            return viaVault(password, ...args);
        }
        throw new Error("PQC Provider not ready (Locked or Missing)");
    };

    const generateSessionKey = withCustody(
        () => window.trustkeys.generateSessionKey(),
        () => vaultService.generateSessionKey(),
    );

    const wrapSessionKey = withCustody(
        (sessionKey, publicKey) => window.trustkeys.wrapSessionKey(sessionKey, publicKey),
        (_pw, sessionKey, publicKey) => vaultService.wrapSessionKey(sessionKey, publicKey),
    );

    const unwrapSessionKey = withCustody(
        (wrappedKey) => window.trustkeys.unwrapSessionKey(wrappedKey),
        (password, wrappedKey) => vaultService.unwrapSessionKey(wrappedKey, password),
        "Enter password to unwrap session key:",
    );

    const unwrapManySessionKeys = withCustody(
        (wrappedKeys) => window.trustkeys.unwrapManySessionKeys
            ? window.trustkeys.unwrapManySessionKeys(wrappedKeys)
            // Older extension without the batch call: one round trip each.
            : Promise.all(wrappedKeys.map(wk => window.trustkeys.unwrapSessionKey(wk))),
        (password, wrappedKeys) => vaultService.unwrapManySessionKeys(wrappedKeys, password),
        // One prompt for the whole batch, not one per key.
        "Enter password to unlock session keys (Batch):",
    );

    // Not withCustody: this one does NOT require custody of a private key when a
    // recipient's public key is supplied, so its second branch is the in-process
    // library rather than the vault, and a locked vault is not an error.
    const encrypt = async (content, publicKey) => {
        if (isExtensionAvailable && window.trustkeys) {
            return await window.trustkeys.encrypt(content, publicKey || mlkemKey);
        } else {
            // Fallback: use the in-process library when a target key is supplied
            // (e.g. encrypting for a contact before the local vault is unlocked).
            if (!publicKey && vaultService.isLocked) {
                // If no public key provided AND vault locked (no mlkemKey), we can't encrypt
                throw new Error("PQC Provider not ready (Locked or Missing)");
            }

            const targetKey = publicKey || mlkemKey;
            if (!targetKey) throw new Error("No encryption key available");

            const { encryptMessagePQC } = await import('../utils/crypto');
            return await encryptMessagePQC(content, targetKey);
        }
    };

    const sign = withCustody(
        (message) => window.trustkeys.sign(message),
        (password, message) => vaultService.sign(message, password),
        "Enter password to sign document:",
    );

    // Sign a chat message (audit S1). Distinct from sign() so it can stay SILENT
    // per message: the extension auto-signs message-domain payloads, and the
    // local vault caches the signing key after a single unlock this session.
    const signMessage = withCustody(
        (body) => window.trustkeys.signMessage
            ? window.trustkeys.signMessage(body)
            // Older extensions without the silent path fall back to sign(),
            // which pops a popup per message but stays functional.
            : window.trustkeys.sign(body),
        (password, body) => vaultService.signMessage(body, password),
        // Skipped once the key is cached, which is what keeps this silent.
        () => vaultService.hasCachedSigningKey()
            ? null
            : "Enter password to enable secure messaging:",
    );

    const decrypt = withCustody(
        (encryptedObject) => window.trustkeys.decrypt(encryptedObject),
        (password, encryptedObject) => vaultService.decrypt(encryptedObject, password),
        "Enter password to decrypt data:",
    );

    const decryptManyViaExtension = async (encryptedObjects) => {
        // Batch API: ONE approval popup for the whole set (audit M-3 — encrypted
        // titles need every item's key on list render).
        if (window.trustkeys.decryptMany) {
            const results = await window.trustkeys.decryptMany(encryptedObjects);
            return results.map(r => r === null ? "Error: Decryption Failed" : r);
        }
        // Older extension: sequential fallback, one popup per item. A single
        // failure must not lose the rest of the list.
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
    };

    const decryptMany = withCustody(
        decryptManyViaExtension,
        (password, encryptedObjects) => vaultService.decryptMany(encryptedObjects, password),
        (encryptedObjects) => `Enter password to decrypt ${encryptedObjects.length} messages:`,
    );

    const getVaultAccounts = () => vaultService.getAccounts();

    const addVaultAccount = async (name) => {
        const password = await requestPassword("Enter password to create new account:");
        const acc = await vaultService.addAccount(name, password);
        return acc;
    };

    const switchVaultAccount = async (id) => {
        const password = await requestPassword("Enter password to switch account:");
        const account = await vaultService.switchAccount(id, password);

        const accountId = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setPqcAccount(accountId);
        setMlkemKey(encryptionKey);

        authLogout();
        // explicit logout forces user to re-login with new identity attempt


        return account;
    };

    // --- Account deletion ---
    //
    // Two modes, and the mode is part of what gets SIGNED: without that a relay
    // could downgrade an erase into a leave (the data the user asked to destroy
    // stays) or escalate a leave into an erase, under a signature the server
    // accepts either way.
    //
    // Erase asks the server which of the user's messages carry a session key
    // other people's messages depend on, and re-signs a redacted form of each
    // — keys kept, ciphertext dropped. Deleting those outright would take the
    // partner's OWN replies with them, since a DM epoch's key lives in the
    // first message under that sid and the replies carry keys:null.
    /**
     * Remove the ACTIVE identity from this device's vault.
     *
     * Scoped to one identity on purpose: a vault can hold several, and the one
     * the server just deleted is the only one that has become useless. The
     * whole vault is wiped only when that identity is the last one in it, since
     * vaultService.deleteAccount refuses to remove the final account — and
     * leaving an empty-but-present vault behind would keep the login screen
     * offering "Unlock Local Vault" with no way to create a new identity.
     *
     * `password` is passed in by callers that already hold it (the login screen
     * has just used it); otherwise it is asked for, or answered from the key
     * cache. Returns which of the two happened, for the caller's message.
     */
    const forgetLocalIdentity = async (password = undefined) => {
        const accounts = vaultService.getAccounts() || [];
        const active = vaultService.getActiveAccount();

        if (accounts.length > 1 && active) {
            const pw = password !== undefined
                ? password
                : await requestPassword("Enter your vault password to remove this identity:");
            await vaultService.deleteAccount(active.id, pw);
            const next = vaultService.getActiveAccount();
            if (next) {
                setPqcAccount(next.mldsa.publicKey);
                setMlkemKey(next.mlkem.publicKey);
            }
            return 'identity';
        }

        vaultService.wipeVault();
        setHasLocalVault(false);
        setBiometricsEnabled(false);
        return 'vault';
    };

    const deleteServerAccount = async (mode, { forgetVault = false } = {}) => {
        let redactions = [];
        if (mode === 'erase') {
            // Paged to the end (audit O-3). Reading only the first page would
            // silently DELETE every carrier past it rather than redacting it —
            // the quiet half of the paging trap, since nothing on screen would
            // say a page was missed.
            const rows = await fetchAllPages(({ limit, offset }) =>
                apiFetch(pageUrl(API_ENDPOINTS.ACCOUNT.REDACTABLE, { limit, offset }), token)
            );
            // `conv` and `gid` come from the server, derived from the row the
            // message was delivered under (audit F-1) — signing a conversation
            // of our own choosing would just produce a signature it rejects.
            redactions = await Promise.all(rows.map(async (row) => ({
                key: row.key,
                signature: await signMessage(await messageSigningBody({
                    from: pqcAccount,
                    conv: row.conv,
                    gid: row.gid,
                    sid: row.sid,
                    keys: row.keys,
                    ct: null,
                })),
            })));
        }

        const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(pqcAccount));
        if (!nonceRes.ok) throw new Error("Failed to fetch nonce");
        const { nonce } = await nonceRes.json();

        // sign(), not signMessage(): this deliberately carries its own context,
        // so the extension shows an approval window instead of auto-signing it.
        const signature = await sign(
            await accountDeletionBody(nonce, mode, redactions.map((r) => r.key))
        );

        await apiFetch(API_ENDPOINTS.ACCOUNT.DELETE, token, {
            method: 'POST',
            body: { mode, nonce, signature, redactions },
        });

        // Erasing blocks the key forever, so the vault entry left behind is a
        // key the server will never admit again — and with it present the login
        // screen only ever offers "Unlock Local Vault", with no way to create a
        // new identity. Removing it is the caller's explicit choice because it
        // is unrecoverable, and it must happen only AFTER the server said yes:
        // every redaction signature needs the key this destroys.
        // Never on a `leave`, whatever the caller asks: the vault is exactly
        // what makes leaving reversible, so removing it would turn the promise
        // on that screen into a lie.
        if (forgetVault && mode === 'erase') await forgetLocalIdentity();

        // Otherwise the vault stays: the keys are the user's, and after a
        // `leave` they are exactly what brings the account back.
        authLogout();
    };

    const deleteVaultAccount = async (id) => {
        const password = await requestPassword("Enter password to DELETE account:");
        await vaultService.deleteAccount(id, password);

        const current = vaultService.getActiveAccount();
        if (current) {
            setPqcAccount(current.mldsa.publicKey);
            setMlkemKey(current.mlkem.publicKey);
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
            mlkemKey,
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
            deleteServerAccount,
            forgetLocalIdentity,
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
                    const password = await requestPassword(
                        "Enter password to ENABLE FaceID/TouchID:",
                        { forcePrompt: true }
                    );
                    const mode = await vaultService.enableBiometrics(password);
                    setBiometricsEnabled(true);
                    return mode; // always 'prf' (enableBiometrics throws on unsupported devices)
                } else {
                    vaultService.disableBiometrics();
                    setBiometricsEnabled(false);
                }
            },
            unlockWithBiometrics: async () => {
                // ONE ceremony for the whole login. This used to call
                // vaultService.unlockWithBiometrics(), which recovers the password
                // internally and throws it away, and then recover it a second time
                // to sign the login challenge — so a single click on "unlock with
                // biometrics" asked the authenticator twice for the same secret.
                const password = await vaultService.recoverPasswordWithBiometrics();
                const success = await vaultService.unlock(password);
                if (!success) {
                    // The ceremony worked and the vault still refused, so the
                    // registration belongs to a vault this device no longer has
                    // (or to a password since changed). Nothing about it can
                    // ever succeed again, and leaving it in place leaves a
                    // fingerprint button that fails every time with no way to
                    // clear it from this screen — so drop it and say why.
                    vaultService.disableBiometrics();
                    setBiometricsEnabled(false);
                    throw new Error(
                        "Biometric unlock no longer matches this vault, so it has been turned off. " +
                        "Sign in with your password, then enable it again."
                    );
                }

                const account = vaultService.getActiveAccount();
                const accountId = account.mldsa.publicKey;
                const encryptionKey = account.mlkem.publicKey;

                setPqcAccount(accountId);
                setMlkemKey(encryptionKey);

                // performServerLogin needs a signing function and vaultService.sign
                // needs the password, so the one we already hold signs the challenge.
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
