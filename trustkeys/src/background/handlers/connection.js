import { state } from '../state.js';
import { saveVaultWithSessionKey, launchPopup, isDevOrigin, isAllowedTrustedOrigin } from '../utils.js';
import { requestApproval } from '../approvals.js';

// Whether the extension currently holds the optional host permission for an
// origin (production origins are granted per-site under a popup user gesture).
const hasHostPermission = async (origin) => {
    try {
        return await chrome.permissions.contains({ origins: [`${origin}/*`] });
    } catch {
        return false;
    }
};

// ─── Existing connection handlers ────────────────────────────

export const handleCheckConnection = (origin) => {
    if (state.isLocked) {
        return { success: true, connected: false, error: "Locked" };
    }
    const isConnected = !!state.vault.permissions[origin];
    return { success: true, connected: isConnected };
};

export const handleConnectAsync = async (origin, sendResponse) => {
    if (state.isLocked) {
        await launchPopup();
        sendResponse({ success: false, error: "Locked - Please unlock extension" });
        return;
    }

    if (state.vault.permissions[origin]) {
        sendResponse({ success: true });
        return;
    }

    await requestApproval({
        type: 'CONNECT',
        origin,
        data: { origin },
        route: 'connect',
        onApprove: async () => {
            state.vault.permissions[origin] = true;
            await saveVaultWithSessionKey();
            sendResponse({ success: true });
        },
        onReject: (err) => sendResponse({ success: false, error: err }),
    });
};

// ─── Dynamic content script registration ─────────────────────

const getContentScriptPaths = () => {
    const manifest = chrome.runtime.getManifest();
    const scripts = manifest.content_scripts || [];
    const mainScript = scripts.find(cs => cs.world === 'MAIN');
    const isolatedScript = scripts.find(cs => cs.world === 'ISOLATED' || !cs.world);
    return {
        main: mainScript?.js?.[0] || 'src/content/api_main.js',
        isolated: isolatedScript?.js?.[0] || 'src/content/index.js'
    };
};

const originToScriptId = (origin) => {
    return 'tk_' + origin.replace(/[^a-zA-Z0-9]/g, '_');
};

export const registerOriginScripts = async (origin) => {
    // Skip dev origins — they're in the static manifest
    if (isDevOrigin(origin)) return;

    // Need the optional host permission (granted per-site via the popup) to
    // inject here. If it's missing (e.g. revoked at chrome://extensions), skip.
    if (!await hasHostPermission(origin)) {
        console.warn(`TrustKeys: no host permission for ${origin}; not registering scripts`);
        return;
    }

    const scriptId = originToScriptId(origin);
    const mainId = `${scriptId}_main`;
    const isolatedId = `${scriptId}_isolated`;

    try {
        const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [mainId, isolatedId] });
        if (existing.length >= 2) return; // Already registered
    } catch {
        // getRegisteredContentScripts may throw if IDs don't exist yet — that's fine
    }

    const paths = getContentScriptPaths();
    const matchPattern = `${origin}/*`;

    try {
        await chrome.scripting.registerContentScripts([
            {
                id: mainId,
                matches: [matchPattern],
                js: [paths.main],
                world: 'MAIN',
                runAt: 'document_start',
                persistAcrossSessions: true
            },
            {
                id: isolatedId,
                matches: [matchPattern],
                js: [paths.isolated],
                world: 'ISOLATED',
                runAt: 'document_idle',
                persistAcrossSessions: true
            }
        ]);
    } catch (e) {
        console.warn(`TrustKeys: Failed to register scripts for ${origin}:`, e);
    }
};

export const unregisterOriginScripts = async (origin) => {
    const scriptId = originToScriptId(origin);
    const ids = [`${scriptId}_main`, `${scriptId}_isolated`];

    try {
        await chrome.scripting.unregisterContentScripts({ ids });
    } catch {
        // May not exist — ignore
    }
};

export const syncDynamicScripts = async () => {
    if (!state.vault?.permissions) return;

    // Reconcile against actual granted permissions: a production trusted origin
    // whose host permission was revoked out-of-band (chrome://extensions) is
    // dropped from the trust list, so "trusted" never outlives the grant.
    let changed = false;
    for (const origin of Object.keys(state.vault.permissions)) {
        if (isDevOrigin(origin)) continue;
        if (!await hasHostPermission(origin)) {
            delete state.vault.permissions[origin];
            if (state.vault.autoSignSites) delete state.vault.autoSignSites[origin];
            changed = true;
        }
    }
    if (changed) await saveVaultWithSessionKey();

    const origins = Object.keys(state.vault.permissions);

    for (const origin of origins) {
        await registerOriginScripts(origin);
    }

    try {
        const allRegistered = await chrome.scripting.getRegisteredContentScripts();
        for (const script of allRegistered) {
            if (!script.id.startsWith('tk_')) continue;
            const isStillPermitted = origins.some(o => script.id.startsWith(originToScriptId(o)));
            if (!isStillPermitted) {
                await chrome.scripting.unregisterContentScripts({ ids: [script.id] });
            }
        }
    } catch (e) {
        console.warn("TrustKeys: Error cleaning stale scripts:", e);
    }
};

// ─── Trusted site management ─────────────────────────────────

export const getTrustedSites = () => {
    const permissions = state.vault?.permissions || {};
    const autoSign = state.vault?.autoSignSites || {};
    return Object.keys(permissions).map(origin => {
        const isDefault = isDevOrigin(origin);
        return {
            origin,
            isDefault,
            // Per-site silent message-signing capability (audit S2/extension
            // hardening). Dev origins are always allowed; added sites default off.
            autoSign: isDefault ? true : !!autoSign[origin],
        };
    });
};

export const handleAddTrustedSite = async (origin, tabId) => {
    if (!origin) return { success: false, error: "Origin required" };
    if (state.isLocked) return { success: false, error: "Vault is locked" };
    // HTTPS-only for production origins (defense in depth — the popup also checks).
    if (!isAllowedTrustedOrigin(origin)) {
        return { success: false, error: "Only HTTPS sites can be trusted" };
    }
    // The optional host permission must already be granted (the popup requests it
    // under a user gesture before calling this). Never inject without it.
    if (!isDevOrigin(origin) && !await hasHostPermission(origin)) {
        return { success: false, error: "Host permission not granted for this site" };
    }

    state.vault.permissions[origin] = true;
    await saveVaultWithSessionKey();
    await registerOriginScripts(origin);

    if (tabId) {
        try { await chrome.tabs.reload(tabId); } catch { /* tab may be gone */ }
    }

    return { success: true };
};

// ─── Authorizing the current tab from the popup ──────────────
//
// The popup cannot be relied on to FINISH an authorization. The host permission
// has to be asked for with chrome.permissions.request, which opens Chrome's own
// dialog; the popup loses focus and closes, and the code that was waiting for
// the answer goes with it. Chrome granted the permission, the vault never
// recorded the site, and the popup offered "Authorize" again next time (found
// in production, 2026-10-15). So the popup first tells the worker which site it
// is about to ask for, and the worker completes the authorization when Chrome
// reports the grant (permissions.onAdded), whether the popup survived or not.
//
// Kept in chrome.storage.session, not memory: the worker can be stopped while
// the user reads Chrome's dialog, and onAdded then wakes a fresh one.

const PENDING_GRANT_KEY = 'tk_pending_site_grant';
const PENDING_GRANT_TTL_MS = 2 * 60 * 1000;

const activeTabOrigin = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return null;
    try {
        return { origin: new URL(tab.url).origin, tabId: tab.id };
    } catch {
        return null;
    }
};

// Trust an origin from the popup's flow. Idempotent: the popup and onAdded can
// both get here for one click, and the second must not reload the tab again.
const trustTabOrigin = async (origin, tabId) => {
    if (!state.isLocked && state.vault?.permissions?.[origin]) {
        return { success: true, origin };
    }
    return { ...(await handleAddTrustedSite(origin, tabId)), origin };
};

export const handleExpectSiteGrant = async () => {
    if (state.isLocked) return { success: false, error: "Vault is locked" };
    const tab = await activeTabOrigin();
    if (!tab) return { success: false, error: 'No active tab or URL not accessible' };
    if (!isAllowedTrustedOrigin(tab.origin)) {
        return { success: false, error: "Only HTTPS sites can be trusted" };
    }
    await chrome.storage.session.set({
        [PENDING_GRANT_KEY]: { ...tab, expires: Date.now() + PENDING_GRANT_TTL_MS },
    });
    return { success: true, origin: tab.origin };
};

// The popup's own completion, when it is still open to send it.
export const handleAuthorizeCurrentTab = async () => {
    const tab = await activeTabOrigin();
    if (!tab) return { success: false, error: 'No active tab or URL not accessible' };
    await chrome.storage.session.remove(PENDING_GRANT_KEY);
    return trustTabOrigin(tab.origin, tab.tabId);
};

// chrome.permissions.onAdded. Only completes what the popup announced: a host
// permission granted any other way (Chrome's own site-access menu) is not a
// decision to let that site use the user's keys.
export const handlePermissionsAdded = async (permissions) => {
    const { [PENDING_GRANT_KEY]: pending } = await chrome.storage.session.get(PENDING_GRANT_KEY);
    if (!pending) return null;
    if (pending.expires < Date.now()) {
        await chrome.storage.session.remove(PENDING_GRANT_KEY);
        return null;
    }
    if (!(permissions?.origins || []).includes(`${pending.origin}/*`)) return null;
    await chrome.storage.session.remove(PENDING_GRANT_KEY);
    return trustTabOrigin(pending.origin, pending.tabId);
};

export const handleRemoveTrustedSite = async (origin) => {
    if (!origin) return { success: false, error: "Origin required" };
    if (state.isLocked) return { success: false, error: "Vault is locked" };

    if (isDevOrigin(origin)) {
        return { success: false, error: "Cannot remove dev default origins" };
    }

    delete state.vault.permissions[origin];
    if (state.vault.autoSignSites) delete state.vault.autoSignSites[origin];
    await saveVaultWithSessionKey();
    await unregisterOriginScripts(origin);
    // Drop the host permission too (doesn't require a user gesture), so removing
    // a site fully revokes the extension's standing access to it.
    try { await chrome.permissions.remove({ origins: [`${origin}/*`] }); } catch { /* best effort */ }

    return { success: true };
};

// Toggle the per-site silent message-signing capability (audit S2). When off,
// the site's message signatures require a per-message approval popup instead.
export const handleSetSiteAutoSign = async (origin, enabled) => {
    if (state.isLocked) return { success: false, error: "Vault is locked" };
    if (!origin || !state.vault.permissions[origin]) {
        return { success: false, error: "Unknown site" };
    }
    if (!state.vault.autoSignSites) state.vault.autoSignSites = {};
    if (enabled) state.vault.autoSignSites[origin] = true;
    else delete state.vault.autoSignSites[origin];
    await saveVaultWithSessionKey();
    return { success: true };
};
