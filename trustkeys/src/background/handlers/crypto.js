import { signMessage, encryptMessage, decryptMessage, verifySignature, generateSessionKey, wrapSessionKey, unwrapSessionKey } from '../../utils/crypto.js';
import { state } from '../state.js';
import { launchPopup } from '../utils.js';

export const handleSignAsync = async (request, sender, sendResponse) => {
    if (state.isLocked) throw new Error("Locked");

    // Check Internal vs External
    if (sender.id === chrome.runtime.id && sender.url && sender.url.includes('index.html')) {
        // Internal Dashboard
        const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId);
        if (!account) throw new Error("No active account");

        const signature = await signMessage(request.message, account.dilithium.privateKey);
        sendResponse({ success: true, signature });
        return;
    }

    // External
    const checkOrigin = sender.origin || request.origin;
    if (!state.vault.permissions[checkOrigin]) {
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
    const checkOrigin = sender.origin || request.origin;
    if (!state.vault.permissions[checkOrigin]) throw new Error("Site not connected");

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
    const checkOrigin = sender.origin || request.origin;
    if (!state.vault.permissions[checkOrigin]) throw new Error("Site not connected");

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
    const checkOrigin = sender.origin || request.origin;
    if (!state.vault.permissions[checkOrigin]) throw new Error("Site not connected");

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
