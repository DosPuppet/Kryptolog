import { createContext, useContext, useState, useEffect, useRef } from 'react';
import API_ENDPOINTS from '../config';
import { useAuth } from './AuthContext';
import { vaultService } from '../services/vault';
import { addressOf, loginChallengeBody, encryptionKeyAttestationBody, messageSigningBody, accountDeletionBody, conversationEraseBody, multisigApprovalMessage } from '../utils/crypto';
import { toast } from '../utils/toast';
import { apiFetch } from '../services/api';
import { PAGE_SIZE as MANIFEST_PAGE, pageUrl } from '../utils/paging';
import PasswordModal from '../components/PasswordModal';

const PQCContext = createContext();

// How many redaction signatures one deletion request may carry. Must not
// exceed the server's MAX_REDACTIONS_PER_DELETE (backend/schemas.py), which
// bounds ONE request rather than the account — an erase with more carriers
// than this takes several rounds. backend/tests/test_account_deletion.py pins
// the two constants against each other, because a client that asked for more
// than the server accepts would 422 on exactly the accounts this exists for.
const REDACTION_ROUND = 1000;

// Runaway guard on those rounds. Each round strictly shrinks the manifest, so
// this is unreachable unless the client and server disagree about what counts
// as redactable — at 1000 per round it allows an account far past any real one.
const MAX_REDACTION_ROUNDS = 50;

export const usePQC = () => {
    const context = useContext(PQCContext);
    if (!context) {
        throw new Error('usePQC must be used within a PQCProvider');
    }
    return context;
};

export const PQCProvider = ({ children }) => {
    const { login: authLogin, logout: authLogout, token } = useAuth();
    const [pqcAccount, setPqcAccount] = useState(null); // this identity's ADDRESS
    // The key that address names (crypto-core 3.3.0): the same string until
    // 4.0.0 makes the address a hash of it. Set only through adoptIdentity.
    const [identityPublicKey, setIdentityPublicKey] = useState(null);
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
            setIdentityPublicKey(null);
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

    // The one way this context takes on an identity: its address, the key
    // that address names, and its encryption key, always together.
    const adoptIdentity = (identityKey, encryptionKey) => {
        setPqcAccount(addressOf(identityKey));
        setIdentityPublicKey(identityKey);
        setMlkemKey(encryptionKey);
    };

    // `signLogin({ nonce, origin, deployment, encryptionKey })` returns the login
    // signature, `attestFn()` the key attestation. Not "sign this string": the
    // extension no longer signs a login body a page hands it (audit 2026-10-12
    // K-03) — it builds the body itself, with the origin the BROWSER reports,
    // so a page cannot obtain a login meant for another site.
    const performServerLogin = async (identityKey, encryptionKey, signLogin, username = null, inviteCode = null, attestFn = null) => {
        // The server checks that the key is the one the address names (3.3.0).
        const address = addressOf(identityKey);

        // 1. Get Nonce
        const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(address));
        if (!nonceRes.ok) throw new Error("Failed to fetch nonce");
        // The deployment id comes with the nonce: both go into the signed body,
        // so the signature is a login HERE and nowhere else (crypto-core 3.0.0,
        // audit 2026-10-12 K-02).
        const { nonce, deployment } = await nonceRes.json();
        const origin = window.location.origin;

        // 2. Sign Nonce — bind the encryption (ML-KEM) key into the challenge so
        //    the identity's signature authorizes it (M-2). The challenge is
        //    domain-separated under the `login` context (H1) so a content-signing
        //    operation can never produce these bytes. Built by crypto-core, not
        //    spelled out here: this is the one string the server must agree with
        //    byte for byte, and a second copy of it cannot be kept honest.
        const signature = await signLogin({ nonce, origin, deployment, encryptionKey });

        // 2b. Key attestation (audit M-1): self-sign our own ML-KEM key so peers
        //     can verify the directory's key binding against our address.
        //     REQUIRED now (audit 2026-10-12 K-04): the server refuses a key
        //     without one, and contacts refuse an unattested key. It used to be
        //     skipped quietly when a custody path could not produce one, which
        //     is the shape a key substitution takes.
        let attestation = null;
        if (encryptionKey) {
            if (!attestFn) throw new Error("This custody path cannot attest its encryption key.");
            attestation = await attestFn();
        }

        // 3. Verify on Backend
        const loginRes = await fetch(API_ENDPOINTS.AUTH.LOGIN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address,
                identity_public_key: identityKey,
                signature,
                nonce,
                origin,
                deployment,
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

    // The local vault signs the bodies this page builds — here the page IS the
    // origin, and window.location.origin is the truth about it.
    const vaultSignLogin = (password) =>
        (args) => vaultService.sign(loginChallengeBody(args), password);
    const vaultAttest = (password, encryptionKey) =>
        () => vaultService.sign(encryptionKeyAttestationBody(encryptionKey), password);

    const loginTrustKeys = async (inviteCode = null) => {
        if (!window.trustkeys) {
            throw new Error("Extension not found");
        }

        const connected = await window.trustkeys.connect();
        if (!connected) throw new Error("Connection request rejected.");

        if (window.trustkeys.handshake) {
            await window.trustkeys.handshake();
        }

        // The extension answers with the account's identity key and encryption
        // key under their own names (3.3.0), deployed together with this page:
        // no fallback to an older extension's field names.
        const tkAccount = await window.trustkeys.getAccount();
        const identityKey = tkAccount.identityPublicKey;
        const encryptionKey = tkAccount.encryptionPublicKey;

        adoptIdentity(identityKey, encryptionKey);

        // inviteCode is only consulted server-side when this is a new identity and
        // invites are required (audit §5); harmless otherwise.
        // Both through dedicated extension APIs (crypto-core 3.0.0): the login
        // body is built inside TrustKeys with the browser-attested origin, and
        // the attestation signs a fixed, self-referential message. No fallback
        // to the generic sign(): it refuses login bodies now (K-03).
        return performServerLogin(
            identityKey,
            encryptionKey,
            ({ nonce, deployment }) => window.trustkeys.signLogin({ nonce, deployment }),
            tkAccount.name,
            inviteCode,
            () => window.trustkeys.getKeyAttestation(),
        );
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
        const identityKey = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        adoptIdentity(identityKey, encryptionKey);

        // Pass known password
        return performServerLogin(identityKey, encryptionKey, vaultSignLogin(password), account.name, inviteCode, vaultAttest(password, encryptionKey));
    };

    const createLocalVault = async (name, password, inviteCode = null) => {
        const account = await vaultService.setup(name, password);
        const identityKey = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setHasLocalVault(true);

        adoptIdentity(identityKey, encryptionKey);

        return performServerLogin(identityKey, encryptionKey, vaultSignLogin(password), name, inviteCode, vaultAttest(password, encryptionKey));
    };

    const importLocalVault = async (json, password, inviteCode = null) => {
        // Create a new local vault from an exported backup, then log in with it.
        const account = await vaultService.importNewVault(json, password);
        const identityKey = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setHasLocalVault(true);
        adoptIdentity(identityKey, encryptionKey);

        return performServerLogin(identityKey, encryptionKey, vaultSignLogin(password), account.name, inviteCode, vaultAttest(password, encryptionKey));
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
        const identityKey = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        setHasLocalVault(true);
        adoptIdentity(identityKey, encryptionKey);

        // The same two helpers as every other local-vault login. This path used
        // to pass `(msg) => vaultService.sign(msg, pw)` — which received the
        // body's FIELDS, not the body, so it signed "[object Object]" — and no
        // attestation at all, so the login threw only after the vault had been
        // written: a device transfer could never finish signing in.
        return performServerLogin(
            identityKey, encryptionKey, vaultSignLogin(newLocalPassword), account.name, inviteCode,
            vaultAttest(newLocalPassword, encryptionKey),
        );
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
    // `forcePrompt` makes the vault path ask for the password even when a
    // derived key is cached — for the one operation where the prompt IS the
    // authorization rather than a way to unlock the key.
    const withCustody = (viaExtension, viaVault, prompt, { forcePrompt = false } = {}) =>
        async (...args) => {
            if (isExtensionAvailable && window.trustkeys) {
                return viaExtension(...args);
            }
            if (!vaultService.isLocked) {
                const ask = typeof prompt === 'function' ? prompt(...args) : prompt;
                const password = ask ? await requestPassword(ask, { forcePrompt }) : undefined;
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

    // Deleting an account, and nothing else, asks for the password EVERY time.
    //
    // The modal chain before it is two dialogs that ConfirmDialogHost clears on
    // Enter, so the claim that "the signing prompt is what makes the sequence a
    // decision" held only while the key cache was cold — which is the default
    // (TTL 0) and nothing else. With a TTL set, `requestPassword` answers null
    // from the cache and an account is destroyed by two keypresses (audit
    // 2026-09-12 L-2).
    //
    // Nothing to do for the extension: its approval window is not skippable,
    // which is why account deletion carries its own signing context in the
    // first place. It builds the body itself from these fields, with the
    // browser-attested origin, and shows the mode and the redaction count in
    // words instead of a raw body (audit 2026-10-12 K-03).
    const signDeletion = withCustody(
        ({ nonce, mode, redactionKeys, deployment }) =>
            window.trustkeys.signAccountDeletion({ nonce, mode, redactionKeys, deployment }),
        async (password, args) => vaultService.sign(await accountDeletionBody(args), password),
        "Enter your vault password to confirm deleting this account:",
        { forcePrompt: true }
    );

    // Erasing one's own messages in ONE conversation (crypto-core 3.1.0, audit
    // 2026-09-11 M-6): the account erase, scoped, and authorized the same way —
    // an approval window in the extension, the password every time with a
    // vault — because the redactions it covers are signed silently.
    const signConversationErase = withCustody(
        ({ nonce, kind, conversation, redactionKeys, deployment }) =>
            window.trustkeys.signConversationErase({ nonce, kind, conversation, redactionKeys, deployment }),
        async (password, args) => vaultService.sign(await conversationEraseBody(args), password),
        "Enter your vault password to confirm erasing your messages in this conversation:",
        { forcePrompt: true }
    );

    // Approving a multisig workflow: the extension builds the approval body and
    // names the workflow in its window rather than showing a hash in context
    // (K-03); the vault signs the same bytes here.
    const signApproval = withCustody(
        ({ workflowId, secretId, ciphertextSha256 }) =>
            window.trustkeys.signMultisigApproval({ workflowId, secretId, ciphertextSha256 }),
        (password, { workflowId, secretId, ciphertextSha256 }) =>
            vaultService.sign(multisigApprovalMessage(workflowId, secretId, ciphertextSha256), password),
        "Enter password to approve this workflow:",
    );

    // Sign a chat message (audit S1). Distinct from sign() so it can stay SILENT
    // per message: the extension auto-signs message-domain payloads, and the
    // local vault caches the signing key after a single unlock this session.
    const signMessage = withCustody(
        // No fallback to sign() for an extension without signMessage: since
        // crypto-core 3.0.0 sign() refuses `message` bodies (audit 2026-10-12
        // K-03), and the cutover ships both sides together.
        (body) => window.trustkeys.signMessage(body),
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

        const identityKey = account.mldsa.publicKey;
        const encryptionKey = account.mlkem.publicKey;

        adoptIdentity(identityKey, encryptionKey);

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
     * Is the identity this session is signed in as the one this device's vault
     * is currently holding open?
     *
     * THE predicate behind every "remove this identity from this device"
     * decision — offered by the danger zone, acted on by forgetLocalIdentity.
     * It lives here, once, because those two call sites disagreeing is exactly
     * what produced the M-1 finding (audit 2026-09-12): the box was offered in
     * a case the code then mishandled.
     *
     * False for an EXTENSION session, which is the case that finding is about.
     * withCustody prefers the extension, so the identity being erased is the
     * extension's, while a vault on the same device holds a DIFFERENT identity
     * — one this operation has no business touching. Being locked, it also
     * reports zero accounts, which is what sent the removal below down its
     * "wipe the whole vault" branch.
     *
     * Compared by ADDRESS rather than by "is a vault present": the vault can be
     * unlocked on an identity the user switched away from, and key material is
     * not recoverable from a wrong guess.
     */
    const vaultHoldsCurrentIdentity = () => {
        // null whenever the vault is locked or absent (vault.js getActiveAccount).
        const active = vaultService.getActiveAccount();
        const held = (active?.mldsa?.publicKey || '').toLowerCase();
        return !!held && held === (pqcAccount || '').toLowerCase();
    };

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
     * cache. Returns what was removed — 'identity', 'vault', or 'none'.
     */
    const forgetLocalIdentity = async (password = undefined) => {
        // Refuse to destroy key material belonging to anyone but the identity
        // this session signed in as (audit 2026-09-12 M-1). Returning rather
        // than throwing: the erase path reaches here AFTER the server has
        // already deleted the account, so raising would report a failure that
        // did not happen — and this is a no-op, not a failed operation.
        if (!vaultHoldsCurrentIdentity()) {
            console.warn(
                "Leaving this device's vault alone: it is not holding the identity being removed."
            );
            return 'none';
        }

        const accounts = vaultService.getAccounts() || [];
        const active = vaultService.getActiveAccount();

        if (accounts.length > 1) {
            const pw = password !== undefined
                ? password
                : await requestPassword("Enter your vault password to remove this identity:");
            await vaultService.deleteAccount(active.id, pw);
            const next = vaultService.getActiveAccount();
            if (next) {
                adoptIdentity(next.mldsa.publicKey, next.mlkem.publicKey);
            }
            return 'identity';
        }

        vaultService.wipeVault();
        setHasLocalVault(false);
        setBiometricsEnabled(false);
        return 'vault';
    };

    /**
     * Read up to one round's worth of the redaction manifest.
     *
     * Paged to the end (audit O-3) but stopped at the server's per-request
     * ceiling: reading only the first page would leave carriers behind, and
     * reading past REDACTION_ROUND would build a request the server refuses
     * whole. Always from offset 0 — redacted rows drop out of the manifest, so
     * each round's read starts where the last one finished without either side
     * tracking an offset.
     */
    const readRedactionRound = async (manifestUrl = API_ENDPOINTS.ACCOUNT.REDACTABLE) => {
        const rows = [];
        while (rows.length < REDACTION_ROUND) {
            // Ask for only what is left of the round, so over-reading is
            // impossible rather than trimmed afterwards — the page size is a
            // shared constant and nothing here should depend on it dividing
            // the round size.
            const limit = Math.min(MANIFEST_PAGE, REDACTION_ROUND - rows.length);
            const got = await apiFetch(
                pageUrl(manifestUrl, { limit, offset: rows.length }),
                token
            );
            if (!Array.isArray(got) || got.length === 0) break;
            rows.push(...got);
            if (got.length < limit) break;
        }
        return rows;
    };

    /** Sign the redacted form of every message in one round. */
    const signRedactions = async (rows) =>
        Promise.all(rows.map(async (row) => ({
            key: row.key,
            // `conv` and `gid` come from the server, derived from the row the
            // message was delivered under (audit F-1) — signing a conversation
            // of our own choosing would just produce a signature it rejects.
            signature: await signMessage(await messageSigningBody({
                from: pqcAccount,
                conv: row.conv,
                gid: row.gid,
                sid: row.sid,
                // The original's signed position (crypto-core 3.0.0): a
                // redaction keeps it, so it is signed again with it.
                ts: row.ts,
                seq: row.seq,
                keys: row.keys,
                ct: null,
            })),
        })));

    /**
     * One signed deletion request. Returns the server's summary, or null when
     * it answered "more to redact first".
     *
     * Each round carries its own nonce and its own deletion signature over
     * exactly the keys it holds, so a relay can neither move a redaction
     * between rounds nor drop one from the set it covers.
     */
    const submitDeletion = async (mode, redactions) => {
        const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(pqcAccount));
        if (!nonceRes.ok) throw new Error("Failed to fetch nonce");
        const { nonce, deployment } = await nonceRes.json();
        const origin = window.location.origin;

        // signDeletion(), not signMessage(): this deliberately carries its own
        // context, so the extension shows an approval window instead of
        // auto-signing it — and the vault asks for the password even when a
        // derived key is cached.
        const signature = await signDeletion({
            nonce, mode, redactionKeys: redactions.map((r) => r.key), origin, deployment,
        });

        const res = await apiFetch(API_ENDPOINTS.ACCOUNT.DELETE, token, {
            method: 'POST',
            body: { mode, nonce, origin, deployment, signature, redactions },
            raw: true,
        });
        return roundOutcome(res, redactions, 'Deletion');
    };

    /**
     * What one signed round answered: the summary, or null for "more to
     * redact first" (409). Shared by the account and the conversation erase,
     * which follow the same contract.
     */
    const roundOutcome = async (res, redactions, what) => {
        const summary = await res.json().catch(() => null);
        if (res.ok) return summary || { redacted: redactions.length, kept: 0 };
        // 409 is not a failure here: this round's redactions landed and the
        // next one is strictly smaller. Anything else is.
        if (res.status === 409 && summary?.status === 'redacting') return null;
        // Every finished round is committed, so a rate limit part-way through a
        // long erase costs time rather than work. Say that, instead of leaving
        // a bare 429 to look like the account is now half-deleted.
        if (res.status === 429) {
            throw new Error(
                'Too many requests while erasing. Everything removed so far is gone for good — ' +
                'wait a minute and start again to continue where it stopped.'
            );
        }
        throw new Error(summary?.detail || `${what} failed (${res.status})`);
    };

    /**
     * Drive signed rounds until the server says done. Every round strictly
     * shrinks the manifest, so this terminates; the guards are for the case
     * where it does not, which would mean the two sides disagree about what is
     * redactable rather than that there is a lot of it.
     */
    const runErase = async (manifestUrl, submitRound) => {
        for (let round = 0; ; round++) {
            if (round >= MAX_REDACTION_ROUNDS) {
                throw new Error('Could not finish erasing: the server keeps asking for more redactions.');
            }
            const rows = await readRedactionRound(manifestUrl);
            const summary = await submitRound(await signRedactions(rows));
            if (summary !== null) return summary;
            if (rows.length === 0) {
                // Nothing left to sign and the server still wants more: looping
                // on an empty round forever is the worst answer.
                throw new Error(
                    'Could not finish erasing: the server is holding messages this app cannot redact.'
                );
            }
        }
    };

    /**
     * Erase the caller's own messages in one conversation, then return the
     * server's summary ({ redacted, deleted, kept }). The other side's
     * messages are not touched — that is the server's rule, not this loop's.
     */
    const eraseConversation = (kind, conversation) => runErase(
        API_ENDPOINTS.CONVERSATIONS.REDACTABLE(kind, conversation),
        async (redactions) => {
            const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(pqcAccount));
            if (!nonceRes.ok) throw new Error("Failed to fetch nonce");
            const { nonce, deployment } = await nonceRes.json();
            const origin = window.location.origin;
            const signature = await signConversationErase({
                nonce, kind, conversation, redactionKeys: redactions.map((r) => r.key), origin, deployment,
            });
            const res = await apiFetch(API_ENDPOINTS.CONVERSATIONS.ERASE(kind, conversation), token, {
                method: 'POST',
                body: { nonce, origin, deployment, signature, redactions },
                raw: true,
            });
            return roundOutcome(res, redactions, 'Erasing');
        }
    );

    const deleteServerAccount = async (mode, { forgetVault = false } = {}) => {
        let summary = null;

        if (mode !== 'erase') {
            summary = await submitDeletion(mode, []);
        } else {
            // An account holding more carriers than one request may carry takes
            // several rounds, each separately signed and approved (audit
            // 2026-09-12 M-2a).
            summary = await runErase(API_ENDPOINTS.ACCOUNT.REDACTABLE, (r) => submitDeletion(mode, r));
        }

        // Erasing blocks the key forever, so the vault entry left behind is a
        // key the server will never admit again — and with it present the login
        // screen only ever offers "Unlock Local Vault", with no way to create a
        // new identity. Removing it is the caller's explicit choice because it
        // is unrecoverable, and it must happen only AFTER the server said yes:
        // every redaction signature needs the key this destroys.
        // Never on a `leave`, whatever the caller asks: the vault is exactly
        // what makes leaving reversible, so removing it would turn the promise
        // on that screen into a lie.
        // And never for an identity the vault is not holding — forgetLocalIdentity
        // checks that itself, so a caller asking for it anyway gets a no-op
        // rather than somebody else's keys destroyed (audit 2026-09-12 M-1).
        if (forgetVault && mode === 'erase') await forgetLocalIdentity();

        // Otherwise the vault stays: the keys are the user's, and after a
        // `leave` they are exactly what brings the account back.
        authLogout();
        return summary;
    };

    const deleteVaultAccount = async (id) => {
        const password = await requestPassword("Enter password to DELETE account:");
        await vaultService.deleteAccount(id, password);

        const current = vaultService.getActiveAccount();
        if (current) {
            adoptIdentity(current.mldsa.publicKey, current.mlkem.publicKey);
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
            identityPublicKey,
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
            signApproval,
            signMessage,
            getVaultAccounts,
            addVaultAccount,
            switchVaultAccount,
            deleteVaultAccount,
            deleteServerAccount,
            eraseConversation,
            forgetLocalIdentity,
            vaultHoldsCurrentIdentity,
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
                const identityKey = account.mldsa.publicKey;
                const encryptionKey = account.mlkem.publicKey;

                adoptIdentity(identityKey, encryptionKey);

                // performServerLogin needs a signing function and vaultService.sign
                // needs the password, so the one we already hold signs the challenge.
                return performServerLogin(identityKey, encryptionKey, vaultSignLogin(password), account.name, null, vaultAttest(password, encryptionKey));
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
