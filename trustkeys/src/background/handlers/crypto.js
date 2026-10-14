import {
    signMessage, encryptMessage, decryptMessage, generateSessionKey, wrapSessionKey,
    unwrapSessionKey, attestEncryptionKey, MESSAGE_SIGNING_PREFIX, SIGNING_CONTEXT, domainSeparate,
    loginChallengeBody, accountDeletionBody, conversationEraseBody, multisigApprovalMessage,
    encryptionSeedFor,
} from '../../utils/crypto.js';
import { state, requireUnlocked, requireActiveAccount, activeAccount, requireConnectedOrigin } from '../state.js';
import { isInternalSender, getSenderOrigin, isDevOrigin } from '../utils.js';
import { requestApproval } from '../approvals.js';

// --- What a PAGE may ask TrustKeys to sign (audit 2026-10-12 K-03) ---
//
// The generic SIGN used to sign any string a connected site sent, so domain
// separation protected nothing: a site could hand over a Kryptolog LOGIN
// challenge, a key attestation or an account deletion and get it signed, the
// approval window showing a raw body no person reads. Now the reserved bodies
// are built HERE, from typed fields, with the origin Chrome attaches to the
// sender — never one the page claims — and shown in words. The generic SIGN
// keeps one Kryptolog context, `content` (a signed document, whose text is what
// the window shows), plus non-Kryptolog text, which no Kryptolog verifier
// accepts as anything.
const CONTEXT_PREFIX = domainSeparate('', '').replace(/\n$/, ''); // "...v1\ncontext="
const contextOf = (message) => {
    if (typeof message !== 'string' || !message.startsWith(CONTEXT_PREFIX)) return null;
    return message.slice(CONTEXT_PREFIX.length).split('\n', 1)[0];
};

/**
 * Ask the user to approve signing `body` for the connected site that sent the
 * request, then sign it with the active account. `kind` and `details` are what
 * the window shows instead of the raw body.
 */
const requestSignature = async ({ sender, sendResponse, kind, details, body }) => {
    const origin = getSenderOrigin(sender);
    requireConnectedOrigin(origin);
    const account = requireActiveAccount();

    await requestApproval({
        type: 'SIGN',
        origin,
        data: { origin, kind, details, account: account.name, message: body },
        route: 'sign',
        onApprove: async () => {
            const active = activeAccount();
            if (!active) return sendResponse({ success: false, error: "No active account" });
            const signature = await signMessage(body, active.identity.seed);
            sendResponse({ success: true, signature });
        },
        onReject: (err) => sendResponse({ success: false, error: err }),
    });
};

export const handleSignAsync = async (request, sender, sendResponse) => {
    requireUnlocked();

    if (isInternalSender(sender)) {
        const account = requireActiveAccount();

        const signature = await signMessage(request.message, account.identity.seed);
        sendResponse({ success: true, signature });
        return;
    }

    const context = contextOf(request.message);
    if (context !== null && context !== SIGNING_CONTEXT.CONTENT) {
        return sendResponse({
            success: false,
            error: `TrustKeys does not sign "${context}" bodies through sign(); use the dedicated API`,
        });
    }

    await requestSignature({
        sender,
        sendResponse,
        kind: context === null ? 'text' : 'content',
        // The document text, without the domain header the person never typed.
        details: context === null ? {} : { text: request.message.slice(CONTEXT_PREFIX.length + context.length + 1) },
        body: request.message,
    });
};

// A Kryptolog login for the site asking, built here (K-02, K-03). The origin is
// the one Chrome attaches to the sender, so a page cannot obtain a login for
// another site; the encryption key is the active account's own.
export const handleSignLoginAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const account = requireActiveAccount();
    const body = loginChallengeBody({
        nonce: request.nonce,
        origin: getSenderOrigin(sender),
        deployment: request.deployment,
        encryptionKey: account.encryption.publicKey,
    });
    await requestSignature({
        sender, sendResponse, kind: 'login', details: { deployment: request.deployment }, body,
    });
};

const REDACTION_KEY = /^(dm|group):[0-9]{1,20}$/;
const MAX_REDACTIONS = 1000;

export const handleSignAccountDeletionAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const keys = request.redactionKeys ?? [];
    if (!Array.isArray(keys) || keys.length > MAX_REDACTIONS || !keys.every((k) => REDACTION_KEY.test(k))) {
        throw new Error("Invalid redaction list");
    }
    const body = await accountDeletionBody({
        nonce: request.nonce,
        mode: request.mode,
        redactionKeys: keys,
        origin: getSenderOrigin(sender),
        deployment: request.deployment,
    });
    await requestSignature({
        sender, sendResponse, kind: 'account-deletion',
        // The address being deleted is shown (crypto-core 4.0.0): with several
        // identities in the vault, "this account" alone does not say which.
        details: {
            mode: request.mode, redactions: keys.length, deployment: request.deployment,
            address: requireActiveAccount().id,
        },
        body,
    });
};

// Erasing one's own messages in ONE conversation (crypto-core 3.1.0, audit
// 2026-09-11 M-6). Built here like the account deletion — the origin is the
// one Chrome attaches — and always asked about: the redactions it authorizes
// are message bodies this extension signs silently, which is the whole reason
// this signature exists.
export const handleSignConversationEraseAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const keys = request.redactionKeys ?? [];
    if (!Array.isArray(keys) || keys.length > MAX_REDACTIONS || !keys.every((k) => REDACTION_KEY.test(k))) {
        throw new Error("Invalid redaction list");
    }
    const body = await conversationEraseBody({
        nonce: request.nonce,
        kind: request.kind,
        conversation: request.conversation,
        redactionKeys: keys,
        origin: getSenderOrigin(sender),
        deployment: request.deployment,
    });
    await requestSignature({
        sender, sendResponse, kind: 'conversation-erase',
        details: {
            conversationKind: request.kind,
            // A partner is named by a 96-character address since crypto-core
            // 4.0.0 (it was a 2 624-character key): short enough to show whole.
            conversation: request.conversation,
            redactions: keys.length,
            deployment: request.deployment,
        },
        body,
    });
};

export const handleSignMultisigApprovalAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const { workflowId, secretId, ciphertextSha384 } = request;
    if (!Number.isSafeInteger(workflowId) || !Number.isSafeInteger(secretId) ||
        typeof ciphertextSha384 !== 'string' || !/^[0-9a-f]{96}$/.test(ciphertextSha384)) {
        throw new Error("Invalid workflow approval request");
    }
    await requestSignature({
        sender, sendResponse, kind: 'multisig-approval',
        details: { workflowId, secretId, ciphertextSha384 },
        body: multisigApprovalMessage(workflowId, secretId, ciphertextSha384),
    });
};

export const handleSignMessage = async (request, sender, sendResponse) => {
    requireUnlocked();

    const message = request.message;
    if (typeof message !== 'string' || !message.startsWith(MESSAGE_SIGNING_PREFIX)) {
        // Not a chat message — refuse (don't silently sign arbitrary bytes).
        return sendResponse({ success: false, error: "signMessage only signs message-context payloads" });
    }

    const internal = isInternalSender(sender);
    const origin = internal ? null : getSenderOrigin(sender);

    if (!internal && (!origin || !state.vault.permissions[origin])) {
        return sendResponse({ success: false, error: "Site not connected" });
    }

    // The localhost exemption is compiled out of production builds
    // (__TRUSTKEYS_ALLOW_DEV_AUTOSIGN__, see vite.config.js): shipping it would
    // let ANY page served from localhost, on any port, sign as the user with no
    // prompt and no per-site grant. In a production build a dev origin gets the
    // same treatment as any other site — silent signing only where the user
    // granted it, otherwise a per-message approval popup.
    const devAutoSign = __TRUSTKEYS_ALLOW_DEV_AUTOSIGN__ && isDevOrigin(origin);
    const silentAllowed = internal || devAutoSign || !!(state.vault.autoSignSites && state.vault.autoSignSites[origin]);
    if (!silentAllowed) {
        // No silent-signing grant for this site → require per-message approval.
        // Not handleSignAsync: that refuses `message` bodies from pages, which
        // is right for the generic API and wrong here, where the body has
        // already been checked to be a chat message.
        return requestSignature({ sender, sendResponse, kind: 'message', details: {}, body: message });
    }

    const account = activeAccount();
    if (!account) return sendResponse({ success: false, error: "No active account" });

    const signature = await signMessage(message, account.identity.seed);
    sendResponse({ success: true, signature });
};

// Encryption-key attestation (audit M-1): the active account self-signs its
// OWN encryption key, naming its own address (crypto-core 4.0.0) so peers (and the server) can verify the directory's
// key binding against the account's identity. No approval popup: the message
// is fixed and built entirely here — the site supplies nothing — and it can
// only ever bind this account's own keys together. Requires unlock + (for
// external callers) a connected origin, same gate as getActiveAccount.
export const handleGetKeyAttestation = async (request, sender, isInternal, senderOrigin) => {
    requireUnlocked();
    if (!isInternal) requireConnectedOrigin(senderOrigin);

    const account = requireActiveAccount();

    const attestation = await attestEncryptionKey(
        { address: account.id, encryptionPublicKey: account.encryption.publicKey }, account.identity.seed
    );
    return { success: true, attestation };
};


export const handleEncrypt = async (request) => {
    let pubKey = request.publicKey;
    if (!pubKey) {
        requireUnlocked();
        const account = requireActiveAccount();
        pubKey = account.encryption.publicKey;
    }
    const result = await encryptMessage(request.message, pubKey);
    return { success: true, result };
};

export const handleGenerateSessionKey = async () => {
    const key = await generateSessionKey();
    return { success: true, key };
};

export const handleWrapSessionKey = async (request) => {
    if (!request.sessionKey || !request.publicKey) {
        throw new Error("Missing sessionKey or publicKey");
    }
    const result = await wrapSessionKey(request.sessionKey, request.publicKey);
    return { success: true, wrappedKey: result };
};

export const handleDecryptAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const checkOrigin = getSenderOrigin(sender);
    requireConnectedOrigin(checkOrigin);

    await requestApproval({
        type: 'DECRYPT',
        origin: checkOrigin,
        data: { origin: checkOrigin, kind: 'data', count: 1 },
        route: 'decrypt',
        onApprove: async () => {
            const account = activeAccount();
            if (!account) return sendResponse({ success: false, error: "No active account" });
            // Whichever of the account's keys the envelope names (crypto-core 5.0.0).
            const decrypted = await decryptMessage(request.data, encryptionSeedFor(account, request.data));
            sendResponse({ success: true, decrypted });
        },
        onReject: (err) => sendResponse({ success: false, error: err }),
    });
};

export const handleUnwrapSessionKeyAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const checkOrigin = getSenderOrigin(sender);
    requireConnectedOrigin(checkOrigin);

    await requestApproval({
        type: 'DECRYPT',
        origin: checkOrigin,
        data: { origin: checkOrigin, kind: 'session-keys', count: 1 },
        route: 'decrypt',
        onApprove: async () => {
            const account = activeAccount();
            if (!account) return sendResponse({ success: false, error: "No active account" });

            try {
                const sessionKey = await unwrapSessionKey(
                    request.wrappedKey, encryptionSeedFor(account, request.wrappedKey)
                );
                sendResponse({ success: true, sessionKey });
            } catch (e) {
                console.error("TrustKeys: Unwrap failed", e);
                sendResponse({ success: false, error: "Unwrap failed: " + e.message });
            }
        },
        onReject: (err) => sendResponse({ success: false, error: err }),
    });
};

// Batch decrypt of PQC envelopes ({kem, iv, content}) — ONE approval popup for
// the whole set instead of one per item. Added for encrypted entry titles
// (audit M-3): the dashboard needs every item's wrapped key decrypted to show
// names, which would otherwise cost N popups per visit.
export const handleDecryptManyAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const checkOrigin = getSenderOrigin(sender);
    requireConnectedOrigin(checkOrigin);

    await requestApproval({
        type: 'DECRYPT',
        origin: checkOrigin,
        data: { origin: checkOrigin, kind: 'data', count: request.items?.length },
        route: 'decrypt',
        onApprove: async () => {
            const account = activeAccount();
            if (!account) return sendResponse({ success: false, error: "No active account" });

            try {
                const items = request.items;
                if (!Array.isArray(items)) throw new Error("Invalid input");

                const results = await Promise.all(items.map(async (blob) => {
                    try {
                        return await decryptMessage(blob, encryptionSeedFor(account, blob));
                    } catch { return null; } // per-item failure -> null, not batch failure
                }));
                sendResponse({ success: true, results });
            } catch (e) {
                console.error("TrustKeys: Batch decrypt failed", e);
                sendResponse({ success: false, error: "Batch decrypt failed: " + e.message });
            }
        },
        onReject: (err) => sendResponse({ success: false, error: err }),
    });
};

// Batch Unwrap
export const handleUnwrapManySessionKeysAsync = async (request, sender, sendResponse) => {
    requireUnlocked();
    const checkOrigin = getSenderOrigin(sender);
    requireConnectedOrigin(checkOrigin);

    await requestApproval({
        type: 'DECRYPT',
        origin: checkOrigin,
        data: { origin: checkOrigin, kind: 'session-keys', count: request.wrappedKeys?.length },
        route: 'decrypt',
        onApprove: async () => {
            const account = activeAccount();
            if (!account) return sendResponse({ success: false, error: "No active account" });

            try {
                const wrappedKeys = request.wrappedKeys;
                if (!Array.isArray(wrappedKeys)) throw new Error("Invalid input");

                const results = await Promise.all(wrappedKeys.map(async (blob) => {
                    try {
                        return await unwrapSessionKey(blob, encryptionSeedFor(account, blob));
                    } catch { return null; }
                }));
                sendResponse({ success: true, sessionKeys: results });
            } catch (e) {
                console.error("TrustKeys: Batch unwrap failed", e);
                sendResponse({ success: false, error: "Batch unwrap failed: " + e.message });
            }
        },
        onReject: (err) => sendResponse({ success: false, error: err }),
    });
};
