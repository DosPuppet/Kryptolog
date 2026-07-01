import { state, getSessionPassword } from '../state.js';
import { saveVault, launchPopup, isDevOrigin, isAllowedTrustedOrigin } from '../utils.js';

// Dev-only origins hardcoded in manifest — cannot be removed
const DEV_ORIGINS = ['http://localhost', 'http://127.0.0.1'];

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

export const handleConnect = async (origin) => {
    if (state.isLocked) {
        await launchPopup();
        return { success: false, error: "Locked - Please unlock extension" };
    }

    if (state.vault.permissions[origin]) {
        return { success: true };
    }

    const reqId = Math.random().toString(36).substr(2, 9);

    const promise = new Promise((resolve) => {
        state.pendingRequests.set(reqId, {
            resolve: () => {
                state.vault.permissions[origin] = true;
                saveVault(getSessionPassword());
                resolve({ success: true });
            },
            reject: (err) => {
                resolve({ success: false, error: err || "Rejected" });
            },
            type: 'CONNECT',
            data: { origin }
        });
    });

    await launchPopup('connect', { requestId: reqId, origin });
    return promise;
};

// Refined handleConnect accepting sendResponse
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

    const reqId = Math.random().toString(36).substr(2, 9);
    state.pendingRequests.set(reqId, {
        resolve: () => {
            state.vault.permissions[origin] = true;
            saveVault(getSessionPassword());
            sendResponse({ success: true });
        },
        reject: (err) => {
            sendResponse({ success: false, error: err || "Rejected" });
        },
        type: 'CONNECT',
        data: { origin }
    });

    await launchPopup('connect', { requestId: reqId, origin });
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
    if (DEV_ORIGINS.some(d => origin.startsWith(d))) return;

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
    } catch (e) {
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
    } catch (e) {
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
        if (DEV_ORIGINS.some(d => origin.startsWith(d))) continue;
        if (!await hasHostPermission(origin)) {
            delete state.vault.permissions[origin];
            if (state.vault.autoSignSites) delete state.vault.autoSignSites[origin];
            changed = true;
        }
    }
    if (changed) await saveVault(getSessionPassword());

    const origins = Object.keys(state.vault.permissions);

    // Register scripts for all permitted origins
    for (const origin of origins) {
        await registerOriginScripts(origin);
    }

    // Clean up stale registrations
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
        const isDefault = DEV_ORIGINS.some(d => origin.startsWith(d));
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
    await saveVault(getSessionPassword());
    await registerOriginScripts(origin);

    if (tabId) {
        try { await chrome.tabs.reload(tabId); } catch (e) { /* tab may be gone */ }
    }

    return { success: true };
};

export const handleRemoveTrustedSite = async (origin) => {
    if (!origin) return { success: false, error: "Origin required" };
    if (state.isLocked) return { success: false, error: "Vault is locked" };

    if (DEV_ORIGINS.some(d => origin.startsWith(d))) {
        return { success: false, error: "Cannot remove dev default origins" };
    }

    delete state.vault.permissions[origin];
    if (state.vault.autoSignSites) delete state.vault.autoSignSites[origin];
    await saveVault(getSessionPassword());
    await unregisterOriginScripts(origin);
    // Drop the host permission too (doesn't require a user gesture), so removing
    // a site fully revokes the extension's standing access to it.
    try { await chrome.permissions.remove({ origins: [`${origin}/*`] }); } catch (e) { /* best effort */ }

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
    await saveVault(getSessionPassword());
    return { success: true };
};
