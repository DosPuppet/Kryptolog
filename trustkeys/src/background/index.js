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

// The message dispatch table.
//
// Each entry is `{ [flags], fn }`. `fn` receives one context object and returns
// the response to send; the wrapper below does the sending, the try/catch and
// the sender gating, so no handler can forget any of them. That was worth
// making structural: the previous 34-arm switch let a new arm ship with the
// wrong guard, or with none, and an arm that forgot to call sendResponse left
// the caller's promise pending until the channel was torn down (audit M-6).
//
// Flags:
//   internal  — extension pages only. isInternalSender, NOT
//               `sender.id === chrome.runtime.id`: a content script carries the
//               extension's id too, so the id alone treats any connected page
//               as the popup. That was audit M-5, and the two approval handlers
//               (the only pair that approves a signature or a decryption) had
//               no check at all. test/messageGating.test.js enumerates every
//               type that must carry this flag.
//   origin    — how to resolve the caller's origin. ALWAYS authoritative
//               (audit M4), never request.origin. Three policies, because the
//               handlers genuinely differ and collapsing them would change
//               behaviour:
//                 'sender'         as-is, may be null, never refused.
//                 'required'       as-is, refused if it cannot be determined.
//                 'unlessInternal' null for extension pages; for anyone else
//                                  as-is, refused if it cannot be determined.
//   raw       — the handler owns sendResponse (it resolves later, behind a user
//               approval), so the wrapper must not send anything itself.
const HANDLERS = {
    // --- Security ---
    GET_STATUS: {
        fn: () => ({ success: true, isLocked: state.isLocked, hasPassword: state.hasPassword }),
    },
    SETUP_PASSWORD: {
        fn: async ({ request }) => {
            await auth.setupPassword(request.password);
            await auth.unlockWithSession(request.password);
            return { success: true };
        },
    },
    UNLOCK: {
        fn: async ({ request }) => {
            const success = await auth.unlockWithSession(request.password);
            if (success) await conn.syncDynamicScripts();
            return { success };
        },
    },
    LOCK: {
        fn: async () => {
            await auth.lockWithSession();
            return { success: true };
        },
    },

    // --- Connection & permissions ---
    CHECK_CONNECTION: {
        origin: 'sender',
        fn: ({ origin }) => conn.handleCheckConnection(origin),
    },
    HANDSHAKE: {
        fn: () => ({ success: true, extensionId: chrome.runtime.id }),
    },
    CONNECT: {
        origin: 'required',
        raw: true,
        // The permission is stored against the authoritative origin so it
        // matches what the crypto gates later check.
        fn: ({ origin, sendResponse }) => conn.handleConnectAsync(origin, sendResponse),
    },

    // --- Approval channel ---
    GET_PENDING_REQUEST: {
        internal: true,
        // No requestId => the next queued request. Lets the popup walk the queue
        // instead of stranding whatever arrived while it was busy (audit M-6).
        fn: ({ request }) => {
            const pending = peekApproval(request.requestId);
            return pending
                ? { success: true, request: pending }
                : { success: false, error: 'Request not found' };
        },
    },
    RESOLVE_REQUEST: {
        internal: true,
        fn: ({ request }) => {
            const { ok, next } = settleApproval(request.requestId, request.approved);
            return { success: ok, next };
        },
    },

    // --- Trusted sites ---
    GET_TRUSTED_SITES: {
        internal: true,
        fn: () => ({ success: true, sites: conn.getTrustedSites() }),
    },
    ADD_TRUSTED_SITE: {
        internal: true,
        fn: ({ request }) => conn.handleAddTrustedSite(request.origin, request.tabId),
    },
    REMOVE_TRUSTED_SITE: {
        internal: true,
        fn: ({ request }) => conn.handleRemoveTrustedSite(request.origin),
    },
    SET_SITE_AUTOSIGN: {
        internal: true,
        fn: ({ request }) => conn.handleSetSiteAutoSign(request.origin, request.enabled),
    },
    AUTHORIZE_CURRENT_TAB: {
        internal: true,
        fn: async () => {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab?.url) {
                return { success: false, error: 'No active tab or URL not accessible' };
            }
            const tabOrigin = new URL(tab.url).origin;
            const res = await conn.handleAddTrustedSite(tabOrigin, tab.id);
            return { ...res, origin: tabOrigin };
        },
    },

    // --- Accounts ---
    CREATE_ACCOUNT: {
        internal: true,
        fn: async ({ request }) => ({ success: true, account: await acct.createAccount(request.name) }),
    },
    GET_ACCOUNTS: {
        internal: true,
        fn: () => ({ success: true, accounts: acct.getAccounts() }),
    },
    SET_ACTIVE_ACCOUNT: {
        internal: true,
        fn: async ({ request }) => {
            await acct.setActiveAccount(request.id);
            return { success: true };
        },
    },
    GET_ACTIVE_ACCOUNT: {
        origin: 'unlessInternal',
        fn: ({ origin }) => ({ success: true, account: acct.getActiveAccount(origin) }),
    },
    DELETE_ACCOUNT: {
        internal: true,
        fn: async ({ request }) => {
            await acct.deleteAccount(request.id);
            return { success: true };
        },
    },
    EXPORT_KEYS: {
        internal: true,
        // The ACTIVE account only (see accounts.requireActiveAccount).
        fn: async ({ request }) => ({
            success: true,
            accounts: [await acct.exportActiveAccount(request.password)],
        }),
    },
    EXPORT_KEYS_ENCRYPTED: {
        internal: true,
        fn: async ({ request }) => ({
            success: true,
            blob: await acct.exportEncryptedVault(request.password, request.passphrase),
        }),
    },
    IMPORT_KEYS: {
        internal: true,
        fn: async ({ request }) => {
            const vaultObj = request.accounts ? { accounts: request.accounts } : request.data;
            // No session password to fall back to any more (audit M-4): an
            // import with no explicit password re-seals under the unlocked
            // session's key. See accounts.importVault.
            const password = request.password;

            if (!vaultObj) return { success: false, error: 'No vault data received' };
            if (!password && state.isLocked) return { success: false, error: 'Session locked' };

            const existingCount = acct.getAccounts().length;
            await acct.importVault(vaultObj, password, request.passphrase);
            return { success: true, count: acct.getAccounts().length - existingCount };
        },
    },

    // --- Crypto ---
    SIGN: {
        raw: true,
        fn: ({ request, sender, sendResponse }) => crypto.handleSignAsync(request, sender, sendResponse),
    },
    SIGN_MESSAGE: {
        raw: true,
        // Silent, domain-restricted chat-message signing (audit S1).
        fn: ({ request, sender, sendResponse }) => crypto.handleSignMessage(request, sender, sendResponse),
    },
    VERIFY: {
        fn: ({ request }) => crypto.handleVerify(request),
    },
    GET_KEY_ATTESTATION: {
        origin: 'unlessInternal',
        // Same gating as GET_ACTIVE_ACCOUNT. No popup — see the handler comment.
        fn: ({ request, sender, isInternal, origin }) =>
            crypto.handleGetKeyAttestation(request, sender, isInternal, origin),
    },
    ENCRYPT: {
        fn: ({ request }) => crypto.handleEncrypt(request),
    },
    DECRYPT: {
        raw: true,
        fn: ({ request, sender, sendResponse }) => crypto.handleDecryptAsync(request, sender, sendResponse),
    },
    GENERATE_SESSION_KEY: {
        fn: () => crypto.handleGenerateSessionKey(),
    },
    WRAP_SESSION_KEY: {
        fn: ({ request }) => crypto.handleWrapSessionKey(request),
    },
    UNWRAP_SESSION_KEY: {
        raw: true,
        fn: ({ request, sender, sendResponse }) =>
            crypto.handleUnwrapSessionKeyAsync(request, sender, sendResponse),
    },
    UNWRAP_MANY_SESSION_KEYS: {
        raw: true,
        fn: ({ request, sender, sendResponse }) =>
            crypto.handleUnwrapManySessionKeysAsync(request, sender, sendResponse),
    },
    DECRYPT_MANY: {
        raw: true,
        fn: ({ request, sender, sendResponse }) =>
            crypto.handleDecryptManyAsync(request, sender, sendResponse),
    },
};

/** Every message type the popup and dashboard may use but a page may not. */
export const INTERNAL_ONLY_TYPES = Object.keys(HANDLERS).filter(t => HANDLERS[t].internal);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        try {
            await initPromise;

            // Only the extension's own pages count as USER activity (audit M-4).
            // This used to run for EVERY message, so any connected page could
            // hold the vault open forever by pinging GET_STATUS on a timer —
            // no user present, and the idle timeout unreachable.
            const isInternal = isInternalSender(sender);
            if (isInternal) touchActivity();

            const entry = HANDLERS[request.type];
            if (!entry) {
                // Always answer (audit M-6). An unknown type used to fall out of
                // the switch without calling sendResponse, leaving the caller's
                // promise pending until the channel was torn down.
                sendResponse({ success: false, error: `Unknown message type: ${request.type}` });
                return;
            }

            if (entry.internal && !isInternal) {
                throw new Error('Unauthorized: Internal use only');
            }

            let origin = null;
            if (entry.origin) {
                const hideFromInternal = entry.origin === 'unlessInternal' && isInternal;
                origin = hideFromInternal ? null : getSenderOrigin(sender);
                const mustHaveOrigin =
                    entry.origin === 'required' || (entry.origin === 'unlessInternal' && !isInternal);
                if (mustHaveOrigin && !origin) {
                    sendResponse({ success: false, error: 'Unknown sender origin' });
                    return;
                }
            }

            const result = await entry.fn({ request, sender, sendResponse, isInternal, origin });
            if (!entry.raw) sendResponse(result);
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
