import { state } from './state.js';
import * as auth from './handlers/auth.js';
import * as conn from './handlers/connection.js';
import * as acct from './handlers/accounts.js';
import * as crypto from './handlers/crypto.js';
import { isInternalSender, getSenderOrigin } from './utils.js';
import { settleApproval, peekApproval, handleWindowClosed } from './approvals.js';
import {
    touchActivity, shouldIdleLock, hardenSessionStorage,
    IDLE_ALARM, IDLE_CHECK_MINUTES,
} from './session.js';

const initializeStorage = async () => {
    hardenSessionStorage();
    const { vaultData } = await chrome.storage.local.get('vaultData');
    state.hasPassword = !!vaultData;

    // Resume from the cached vault KEY, never a stored password (audit M-4).
    // readSession() applies the idle window and wipes an expired session, so an
    // expired one can't be resumed here.
    if (await auth.restoreSession()) {
        await conn.syncDynamicScripts();
    }
};
// Initialize storage and capture promise
let initPromise = initializeStorage();

// Idle auto-lock (audit M-4). The old check ran ONLY inside initializeStorage,
// i.e. only when the service worker happened to restart — while it stayed alive
// nothing ever re-checked and the vault stayed unlocked indefinitely. An alarm
// wakes a sleeping worker, so the timeout is now actually enforced.
chrome.alarms.create(IDLE_ALARM, { periodInMinutes: IDLE_CHECK_MINUTES });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name !== IDLE_ALARM) return;
    (async () => {
        if (await shouldIdleLock()) await auth.lockWithSession();
    })();
});

// Dismissing the approval window is a refusal: settle everything it was asking
// about (audit M-6). Previously those promises never settled and their Map
// entries were never removed.
chrome.windows.onRemoved.addListener(handleWindowClosed);

// Message Handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        try {
            await initPromise; // Wait for initialization to complete

            // Only the extension's own pages count as USER activity (audit M-4).
            // This used to run for EVERY message, so any connected page could
            // hold the vault open forever by pinging GET_STATUS on a timer —
            // no user present, and the idle timeout unreachable.
            if (isInternalSender(sender)) touchActivity();

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
                //
                // Every other internal handler carried a sender guard; these two
                // — the ONLY pair that approves a signature or a decryption —
                // had none (audit M-5). Not reachable today (the ISOLATED-world
                // content script relays a fixed type list, and
                // externally_connectable declares no ids), but a missing guard
                // on the approval path is the worst place to rely on that.
                //
                // isInternalSender, not `sender.id === chrome.runtime.id`: a
                // content script also carries the extension's id, so the id
                // alone would treat any connected page as the popup.
                case 'GET_PENDING_REQUEST': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
                    // No requestId => the next queued request. Lets the popup
                    // walk the queue instead of stranding whatever arrived while
                    // it was busy (audit M-6).
                    const pending = peekApproval(request.requestId);
                    if (!pending) {
                        sendResponse({ success: false, error: "Request not found" });
                    } else {
                        sendResponse({ success: true, request: pending });
                    }
                    break;
                }
                case 'RESOLVE_REQUEST': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
                    const { ok, next } = settleApproval(request.requestId, request.approved);
                    sendResponse({ success: ok, next });
                    break;
                }

                // --- Trusted Sites ---
                //
                // Everything below is popup-only, and every one of these guards
                // used to read `sender.id !== chrome.runtime.id` — which a
                // CONTENT SCRIPT passes, because it also runs under the
                // extension's id. Same defect as audit M-5, twelve more times,
                // and it covered DELETE_ACCOUNT and EXPORT_KEYS. What kept it
                // unreachable was the ISOLATED-world relay's fixed type list,
                // not the check itself. isInternalSender additionally requires
                // the extension-page URL, which only the popup/dashboard has.
                case 'GET_TRUSTED_SITES': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized");
                    sendResponse({ success: true, sites: conn.getTrustedSites() });
                    break;
                }
                case 'ADD_TRUSTED_SITE': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized");
                    const addRes = await conn.handleAddTrustedSite(request.origin, request.tabId);
                    sendResponse(addRes);
                    break;
                }
                case 'REMOVE_TRUSTED_SITE': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized");
                    const removeRes = await conn.handleRemoveTrustedSite(request.origin);
                    sendResponse(removeRes);
                    break;
                }
                case 'SET_SITE_AUTOSIGN': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized");
                    const autoRes = await conn.handleSetSiteAutoSign(request.origin, request.enabled);
                    sendResponse(autoRes);
                    break;
                }
                case 'AUTHORIZE_CURRENT_TAB': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized");
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
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
                    const account = await acct.createAccount(request.name);
                    sendResponse({ success: true, account });
                    break;
                }
                case 'GET_ACCOUNTS': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
                    const accounts = acct.getAccounts();
                    sendResponse({ success: true, accounts });
                    break;
                }
                case 'SET_ACTIVE_ACCOUNT': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
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
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
                    try {
                        await acct.deleteAccount(request.id);
                        sendResponse({ success: true });
                    } catch (e) {
                        sendResponse({ success: false, error: e.message });
                    }
                    break;
                }
                case 'EXPORT_KEYS': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
                    // Export the ACTIVE account only (see accounts.requireActiveAccount).
                    const active = await acct.exportActiveAccount(request.password);
                    sendResponse({ success: true, accounts: [active] });
                    break;
                }
                case 'EXPORT_KEYS_ENCRYPTED': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");
                    const blob = await acct.exportEncryptedVault(request.password, request.passphrase);
                    sendResponse({ success: true, blob });
                    break;
                }
                case 'IMPORT_KEYS': {
                    if (!isInternalSender(sender)) throw new Error("Unauthorized: Internal use only");

                    const vaultObj = request.accounts ? { accounts: request.accounts } : request.data;
                    // No session password to fall back to any more (audit M-4):
                    // an import with no explicit password re-seals under the
                    // unlocked session's key. See accounts.importVault.
                    const password = request.password;

                    if (!vaultObj) {
                        return sendResponse({ success: false, error: "No vault data received" });
                    }

                    if (!password && state.isLocked) {
                        return sendResponse({ success: false, error: "Session locked" });
                    }

                    try {
                        const existingCount = acct.getAccounts().length;
                        await acct.importVault(vaultObj, password, request.passphrase);
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
                case 'SIGN_MESSAGE': {
                    // Silent, domain-restricted chat-message signing (audit S1).
                    await crypto.handleSignMessage(request, sender, sendResponse);
                    break;
                }
                case 'VERIFY': {
                    const res = await crypto.handleVerify(request);
                    sendResponse(res);
                    break;
                }
                case 'GET_KEY_ATTESTATION': {
                    // Same sender gating as GET_ACTIVE_ACCOUNT (audit M4): internal
                    // pages pass, external callers need their authoritative origin
                    // to be a connected site. No popup — see handler comment.
                    const isInternal = isInternalSender(sender);
                    const checkOrigin = isInternal ? null : getSenderOrigin(sender);
                    if (!isInternal && !checkOrigin) {
                        sendResponse({ success: false, error: "Unknown sender origin" });
                        break;
                    }
                    const res = await crypto.handleGetKeyAttestation(request, sender, isInternal, checkOrigin);
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
                case 'DECRYPT_MANY': {
                    await crypto.handleDecryptManyAsync(request, sender, sendResponse);
                    break;
                }
                default:
                    // Always answer (audit M-6). An unknown type used to fall out
                    // of the switch without calling sendResponse, leaving the
                    // caller's promise pending until the channel was torn down.
                    sendResponse({ success: false, error: `Unknown message type: ${request.type}` });
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
