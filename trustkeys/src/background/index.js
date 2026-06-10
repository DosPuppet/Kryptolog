import { state, getSessionPassword } from './state.js';
import * as auth from './handlers/auth.js';
import * as conn from './handlers/connection.js';
import * as acct from './handlers/accounts.js';
import * as crypto from './handlers/crypto.js';
import { updateActivity, isInternalSender, getSenderOrigin } from './utils.js';

const initializeStorage = async () => {
    const { vaultData } = await chrome.storage.local.get('vaultData');
    state.hasPassword = !!vaultData;

    try {
        const session = await chrome.storage.session.get(['sessionPassword', 'lastActive']);
        if (session.sessionPassword && session.lastActive) {
            const ONE_HOUR = 60 * 60 * 1000;
            if (Date.now() - session.lastActive < ONE_HOUR) {
                const success = await auth.unlockWithSession(session.sessionPassword);
                if (success) {
                    await chrome.storage.session.set({ lastActive: Date.now() });
                    await conn.syncDynamicScripts();
                }
            } else {
                await chrome.storage.session.remove(['sessionPassword', 'lastActive']);
            }
        }
    } catch (e) {
        console.warn("Session restore failed", e);
    }
};
// Initialize storage and capture promise
let initPromise = initializeStorage();

// Message Handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        try {
            await initPromise; // Wait for initialization to complete
            updateActivity();

            switch (request.type) {
                // --- Security ---
                case 'GET_STATUS': {
                    sendResponse({
                        success: true,
                        isLocked: state.isLocked,
                        hasPassword: state.hasPassword
                    });
                    break;
                }
                case 'SETUP_PASSWORD': {
                    await auth.setupPassword(request.password);
                    await auth.unlockWithSession(request.password);
                    sendResponse({ success: true });
                    break;
                }
                case 'UNLOCK': {
                    const success = await auth.unlockWithSession(request.password);
                    if (success) await conn.syncDynamicScripts();
                    sendResponse({ success });
                    break;
                }
                case 'LOCK': {
                    await auth.lockWithSession();
                    sendResponse({ success: true });
                    break;
                }

                // --- Connection & Permissions ---
                case 'CHECK_CONNECTION': {
                    // Authoritative origin only (audit M4) — never request.origin.
                    const origin = getSenderOrigin(sender);
                    sendResponse(conn.handleCheckConnection(origin));
                    break;
                }
                case 'HANDSHAKE': {
                    sendResponse({ success: true, extensionId: chrome.runtime.id });
                    break;
                }
                case 'CONNECT': {
                    // Connect the authoritative sender origin (audit M4), so the
                    // permission we store matches what the crypto gates check.
                    const origin = getSenderOrigin(sender);
                    if (!origin) {
                        sendResponse({ success: false, error: "Unknown sender origin" });
                        break;
                    }
                    await conn.handleConnectAsync(origin, sendResponse);
                    // Async handler handles sendResponse
                    break;
                }

                // --- Approval Handling ---
                case 'GET_PENDING_REQUEST': {
                    const req = state.pendingRequests.get(request.requestId);
                    if (!req) {
                        sendResponse({ success: false, error: "Request not found" });
                    } else {
                        sendResponse({ success: true, request: { type: req.type, data: req.data } });
                    }
                    break;
                }
                case 'RESOLVE_REQUEST': {
                    const req = state.pendingRequests.get(request.requestId);
                    if (!req) return sendResponse({ success: false });

                    if (request.approved) {
                        req.resolve();
                    } else {
                        req.reject();
                    }
                    state.pendingRequests.delete(request.requestId);
                    sendResponse({ success: true });
                    break;
                }

                // --- Trusted Sites ---
                case 'GET_TRUSTED_SITES': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized");
                    sendResponse({ success: true, sites: conn.getTrustedSites() });
                    break;
                }
                case 'ADD_TRUSTED_SITE': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized");
                    const addRes = await conn.handleAddTrustedSite(request.origin, request.tabId);
                    sendResponse(addRes);
                    break;
                }
                case 'REMOVE_TRUSTED_SITE': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized");
                    const removeRes = await conn.handleRemoveTrustedSite(request.origin);
                    sendResponse(removeRes);
                    break;
                }
                case 'AUTHORIZE_CURRENT_TAB': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized");
                    try {
                        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                        if (!tab?.url) {
                            sendResponse({ success: false, error: "No active tab or URL not accessible" });
                            break;
                        }
                        const tabOrigin = new URL(tab.url).origin;
                        const res = await conn.handleAddTrustedSite(tabOrigin, tab.id);
                        sendResponse({ ...res, origin: tabOrigin });
                    } catch (e) {
                        sendResponse({ success: false, error: e.message });
                    }
                    break;
                }

                // --- Accounts ---
                case 'CREATE_ACCOUNT': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized: Internal use only");
                    const account = await acct.createAccount(request.name);
                    sendResponse({ success: true, account });
                    break;
                }
                case 'GET_ACCOUNTS': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized: Internal use only");
                    const accounts = acct.getAccounts();
                    sendResponse({ success: true, accounts });
                    break;
                }
                case 'SET_ACTIVE_ACCOUNT': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized: Internal use only");
                    await acct.setActiveAccount(request.id);
                    sendResponse({ success: true });
                    break;
                }
                case 'GET_ACTIVE_ACCOUNT': {
                    // Content scripts also carry sender.id === chrome.runtime.id, so
                    // the id alone wrongly treats any page as internal. Use the proper
                    // extension-page check, and gate external callers on the
                    // authoritative sender.origin only (audit M4) — deny if absent.
                    const isInternal = isInternalSender(sender);
                    const checkOrigin = isInternal ? null : getSenderOrigin(sender);
                    if (!isInternal && !checkOrigin) {
                        sendResponse({ success: false, error: "Unknown sender origin" });
                        break;
                    }
                    try {
                        const account = acct.getActiveAccount(checkOrigin);
                        sendResponse({ success: true, account });
                    } catch (e) {
                        sendResponse({ success: false, error: e.message });
                    }
                    break;
                }
                case 'DELETE_ACCOUNT': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized: Internal use only");
                    try {
                        await acct.deleteAccount(request.id);
                        sendResponse({ success: true });
                    } catch (e) {
                        sendResponse({ success: false, error: e.message });
                    }
                    break;
                }
                case 'EXPORT_KEYS': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized: Internal use only");
                    const vaultData = await acct.exportVault(request.password);
                    // Match the key name expected by App.jsx handleExportKeys (res.accounts)
                    sendResponse({ success: true, accounts: vaultData.accounts });
                    break;
                }
                case 'IMPORT_KEYS': {
                    if (sender.id !== chrome.runtime.id) throw new Error("Unauthorized: Internal use only");

                    const vaultObj = request.accounts ? { accounts: request.accounts } : request.data;
                    const password = request.password || getSessionPassword();

                    if (!vaultObj) {
                        return sendResponse({ success: false, error: "No vault data received" });
                    }

                    if (!password) return sendResponse({ success: false, error: "Session locked" });

                    try {
                        const existingCount = acct.getAccounts().length;
                        await acct.importVault(vaultObj, password);
                        const newCount = acct.getAccounts().length;
                        sendResponse({ success: true, count: newCount - existingCount });
                    } catch (e) {
                        console.error("TrustKeys Import Error:", e);
                        sendResponse({ success: false, error: e.message });
                    }
                    break;
                }

                // --- Crypto ---
                case 'SIGN': {
                    await crypto.handleSignAsync(request, sender, sendResponse);
                    break;
                }
                case 'VERIFY': {
                    const res = await crypto.handleVerify(request);
                    sendResponse(res);
                    break;
                }
                case 'ENCRYPT': {
                    const res = await crypto.handleEncrypt(request);
                    sendResponse(res);
                    break;
                }
                case 'DECRYPT': {
                    await crypto.handleDecryptAsync(request, sender, sendResponse);
                    break;
                }
                case 'GENERATE_SESSION_KEY': {
                    const res = await crypto.handleGenerateSessionKey();
                    sendResponse(res);
                    break;
                }
                case 'WRAP_SESSION_KEY': {
                    const res = await crypto.handleWrapSessionKey(request);
                    sendResponse(res);
                    break;
                }
                case 'UNWRAP_SESSION_KEY': {
                    await crypto.handleUnwrapSessionKeyAsync(request, sender, sendResponse);
                    break;
                }
                case 'UNWRAP_MANY_SESSION_KEYS': {
                    await crypto.handleUnwrapManySessionKeysAsync(request, sender, sendResponse);
                    break;
                }
            }
        } catch (error) {
            console.error('Background error:', error);
            sendResponse({ success: false, error: error.message });
        }
    })();
    return true; // Keep channel open
});

// External Message Handler
chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
    (async () => {
        try {
            switch (request.type) {
                case 'CHECK_CONNECTION':
                    sendResponse({ success: true, connected: true, version: '1.0.0' });
                    break;
                case 'IS_CONNECTED': {
                    const origin = sender.origin;
                    if (state.vault && state.vault.permissions) {
                        sendResponse({ success: true, connected: !!state.vault.permissions[origin] });
                    } else {
                        sendResponse({ success: true, connected: false });
                    }
                    break;
                }
                default:
                    sendResponse({ success: false, error: 'Unknown external message type' });
            }
        } catch (error) {
            console.error('External background error:', error);
            sendResponse({ success: false, error: error.message });
        }
    })();
    return true;
});
