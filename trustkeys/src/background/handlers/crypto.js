import { signMessage, encryptMessage, decryptMessage, verifySignature, generateSessionKey, wrapSessionKey, unwrapSessionKey, MESSAGE_SIGNING_PREFIX } from '../../utils/crypto.js';
import { state } from '../state.js';
import { launchPopup, isInternalSender, getSenderOrigin, isDevOrigin } from '../utils.js';

export const handleSignAsync = async (request, sender, sendResponse) => {
    if (state.isLocked) throw new Error("Locked");

    // Check Internal vs External
    if (isInternalSender(sender)) {
        // Internal Dashboard
        const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
        if (!account) throw new Error("No active account");

        const signature = await signMessage(request.message, account.dilithium.privateKey);
        sendResponse({ success: true, signature });
        return;
    }

    // External — authorize on Chrome's sender.origin only (audit M4).
    const checkOrigin = getSenderOrigin(sender);
    if (!checkOrigin || !state.vault.permissions[checkOrigin]) {
        throw new Error("Site not connected");
    }

    const reqId = Math.random().toString(36).substr(2, 9);
    state.pendingRequests.set(reqId, {
        resolve: async () => {
            const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
            if (!account) return sendResponse({ success: false, error: "No active account" });
            const signature = await signMessage(request.message, account.dilithium.privateKey);
            sendResponse({ success: true, signature });
        },
        reject: (err) => sendResponse({ success: false, error: err || "Rejected" }),
        type: 'SIGN',
        data: { origin: checkOrigin, message: request.message }
    });

    await launchPopup('sign', { requestId: reqId });
};

// Silent message signing (audit S1). Unlike handleSignAsync (which pops an
// approval for external sites), this can auto-sign WITHOUT a popup so chat is
// usable — but with two boundaries:
//   1. Domain: ONLY payloads in the `message` context (prefix check), so a site
//      can never use this to mint a login / multisig / content signature.
//   2. Per-site capability: silent signing is only granted to sites the user
//      explicitly trusted for it (autoSignSites), plus dev origins. For other
//      connected sites we fall back to a per-message approval popup, so trusting
//      a site for connection alone does NOT grant silent signing-as-you.
export const handleSignMessage = async (request, sender, sendResponse) => {
    if (state.isLocked) throw new Error("Locked");

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

    const silentAllowed = internal || isDevOrigin(origin) || !!(state.vault.autoSignSites && state.vault.autoSignSites[origin]);
    if (!silentAllowed) {
        // No silent-signing grant for this site → require per-message approval.
        return handleSignAsync(request, sender, sendResponse);
    }

    const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
    if (!account) return sendResponse({ success: false, error: "No active account" });

    const signature = await signMessage(message, account.dilithium.privateKey);
    sendResponse({ success: true, signature });
};

export const handleVerify = async (request) => {
    // Pure ML-DSA-44 signature check — no private key, no user approval needed.
    if (!request.message || !request.signature || !request.publicKey) {
        return { success: true, isValid: false };
    }
    const isValid = await verifySignature(request.message, request.signature, request.publicKey);
    return { success: true, isValid };
};

export const handleEncrypt = async (request) => {
    let pubKey = request.publicKey;
    if (!pubKey) {
        if (state.isLocked) throw new Error("Locked");
        const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
        if (!account) throw new Error("No active account");
        pubKey = account.kyber.publicKey;
    }
    const result = await encryptMessage(request.message, pubKey);
    return { success: true, result };
};

export const handleGenerateSessionKey = async () => {
    const key = await generateSessionKey();
    return { success: true, key };
};

export const handleWrapSessionKey = async (request) => {
    // wrapSessionKey(sessionKeyHex, publicKeyHex)
    if (!request.sessionKey || !request.publicKey) {
        throw new Error("Missing sessionKey or publicKey");
    }
    const result = await wrapSessionKey(request.sessionKey, request.publicKey);
    return { success: true, wrappedKey: result };
};

export const handleDecryptAsync = async (request, sender, sendResponse) => {
    if (state.isLocked) throw new Error("Locked");
    const checkOrigin = getSenderOrigin(sender);
    if (!checkOrigin || !state.vault.permissions[checkOrigin]) throw new Error("Site not connected");

    const reqId = Math.random().toString(36).substr(2, 9);
    state.pendingRequests.set(reqId, {
        resolve: async () => {
            const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
            if (!account) return sendResponse({ success: false, error: "No active account" });
            const decrypted = await decryptMessage(request.data, account.kyber.privateKey);
            sendResponse({ success: true, decrypted });
        },
        reject: (err) => sendResponse({ success: false, error: err || "Rejected" }),
        type: 'DECRYPT',
        data: { origin: checkOrigin }
    });

    await launchPopup('decrypt', { requestId: reqId });
};

export const handleUnwrapSessionKeyAsync = async (request, sender, sendResponse) => {
    if (state.isLocked) throw new Error("Locked");
    const checkOrigin = getSenderOrigin(sender);
    if (!checkOrigin || !state.vault.permissions[checkOrigin]) throw new Error("Site not connected");

    const reqId = Math.random().toString(36).substr(2, 9);
    state.pendingRequests.set(reqId, {
        resolve: async () => {
            const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
            if (!account) return sendResponse({ success: false, error: "No active account" });

            try {
                const sessionKey = await unwrapSessionKey(request.wrappedKey, account.kyber.privateKey);
                sendResponse({ success: true, sessionKey });
            } catch (e) {
                console.error("TrustKeys: Unwrap failed", e);
                sendResponse({ success: false, error: "Unwrap failed: " + e.message });
            }
        },
        reject: (err) => sendResponse({ success: false, error: err || "Rejected" }),
        type: 'DECRYPT',
        data: { origin: checkOrigin }
    });

    await launchPopup('decrypt', { requestId: reqId });
};

// Batch Unwrap
export const handleUnwrapManySessionKeysAsync = async (request, sender, sendResponse) => {
    if (state.isLocked) throw new Error("Locked");
    const checkOrigin = getSenderOrigin(sender);
    if (!checkOrigin || !state.vault.permissions[checkOrigin]) throw new Error("Site not connected");

    const reqId = Math.random().toString(36).substr(2, 9);
    state.pendingRequests.set(reqId, {
        resolve: async () => {
            const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
            if (!account) return sendResponse({ success: false, error: "No active account" });

            try {
                const wrappedKeys = request.wrappedKeys;
                if (!Array.isArray(wrappedKeys)) throw new Error("Invalid input");

                const privKey = account.kyber.privateKey;
                const results = await Promise.all(wrappedKeys.map(async (blob) => {
                    try {
                        return await unwrapSessionKey(blob, privKey);
                    } catch (e) { return null; }
                }));
                sendResponse({ success: true, sessionKeys: results });
            } catch (e) {
                console.error("TrustKeys: Batch unwrap failed", e);
                sendResponse({ success: false, error: "Batch unwrap failed: " + e.message });
            }
        },
        reject: (err) => sendResponse({ success: false, error: err || "Rejected" }),
        type: 'DECRYPT',
        data: { origin: checkOrigin, count: request.wrappedKeys?.length }
    });

    await launchPopup('decrypt', { requestId: reqId });
};
