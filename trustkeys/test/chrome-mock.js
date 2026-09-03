// Minimal chrome.* harness for the background service worker.
//
// The extension is the key custodian and had no test runner at all, so its
// security boundaries — who counts as an internal sender, which sites may sign
// silently, when the vault locks — were only ever verified by hand. This mock
// exists to make those assertable.
//
// Two deliberate fidelity choices, because both model a real constraint the
// production code has to respect:
//   • storage round-trips through JSON, exactly like chrome.storage does. A
//     CryptoKey or Uint8Array written here comes back as `{}` / an object of
//     numeric keys, which is precisely why the vault key has to be persisted as
//     hex (audit M-4).
//   • a content script's sender carries `id === chrome.runtime.id` AND an
//     origin, so `pageSender()` is what proves the id alone can't mean
//     "internal".

import { vi } from 'vitest';

export const EXT_ID = 'trustkeys-test-extension-id';

const makeStorageArea = (seed = {}) => {
    const data = new Map(Object.entries(seed));
    // chrome.storage is JSON-serialized, not structured-clone.
    const store = (v) => JSON.parse(JSON.stringify(v ?? null));
    return {
        _data: data,
        get: vi.fn(async (keys) => {
            const out = {};
            const list = keys == null ? [...data.keys()]
                : typeof keys === 'string' ? [keys]
                    : Array.isArray(keys) ? keys : Object.keys(keys);
            for (const k of list) if (data.has(k)) out[k] = data.get(k);
            return out;
        }),
        set: vi.fn(async (obj) => {
            for (const [k, v] of Object.entries(obj)) data.set(k, store(v));
        }),
        remove: vi.fn(async (keys) => {
            for (const k of (Array.isArray(keys) ? keys : [keys])) data.delete(k);
        }),
        clear: vi.fn(async () => data.clear()),
    };
};

export const installChrome = ({ local: localSeed = {}, session: sessionSeed = {} } = {}) => {
    const listeners = { message: [], external: [], alarm: [], windowRemoved: [] };
    const local = makeStorageArea(localSeed);
    const session = makeStorageArea(sessionSeed);
    const windows = new Map();
    let nextWindowId = 1;

    const chrome = {
        runtime: {
            id: EXT_ID,
            lastError: null,
            getManifest: () => ({
                content_scripts: [
                    { world: 'MAIN', js: ['src/content/api_main.js'] },
                    { world: 'ISOLATED', js: ['src/content/index.js'] },
                ],
            }),
            onMessage: { addListener: (fn) => listeners.message.push(fn) },
            onMessageExternal: { addListener: (fn) => listeners.external.push(fn) },
        },
        storage: {
            local,
            session: { ...session, setAccessLevel: vi.fn(async () => { }) },
        },
        alarms: {
            create: vi.fn(),
            clear: vi.fn(),
            onAlarm: { addListener: (fn) => listeners.alarm.push(fn) },
        },
        windows: {
            create: vi.fn(async (opts) => {
                const id = nextWindowId++;
                windows.set(id, opts);
                return { id, ...opts };
            }),
            update: vi.fn(async (id) => {
                if (!windows.has(id)) throw new Error(`No window with id ${id}`);
                return { id };
            }),
            getLastFocused: vi.fn(async () => ({ left: 0, top: 0, width: 1200, height: 800 })),
            onRemoved: { addListener: (fn) => listeners.windowRemoved.push(fn) },
        },
        tabs: {
            query: vi.fn(async () => [{ id: 1, url: 'https://app.example/page' }]),
            reload: vi.fn(async () => { }),
            update: vi.fn(async () => { }),
        },
        permissions: {
            contains: vi.fn(async () => true),
            remove: vi.fn(async () => true),
        },
        scripting: {
            getRegisteredContentScripts: vi.fn(async () => []),
            registerContentScripts: vi.fn(async () => { }),
            unregisterContentScripts: vi.fn(async () => { }),
        },
    };

    globalThis.chrome = chrome;

    return {
        chrome,
        sessionStore: session._data,
        localStore: local._data,
        openWindows: windows,

        /** Deliver a runtime message; resolves with the handler's response. */
        send(request, sender = pageSender()) {
            return new Promise((resolve) => {
                let done = false;
                const sendResponse = (r) => { if (!done) { done = true; resolve(r); } };
                for (const fn of listeners.message) fn(request, sender, sendResponse);
            });
        },

        fireAlarm(name) {
            for (const fn of listeners.alarm) fn({ name });
        },

        /** Dismiss a window the way a user closing it would. */
        closeWindow(id) {
            windows.delete(id);
            for (const fn of listeners.windowRemoved) fn(id);
        },

        lastWindowId() {
            const ids = [...windows.keys()];
            return ids.length ? ids[ids.length - 1] : null;
        },
    };
};

/** The extension's own pages (popup / dashboard). */
export const internalSender = (query = '') => ({
    id: EXT_ID,
    url: `chrome-extension://${EXT_ID}/index.html${query}`,
});

/**
 * A content script. Carries the extension's id — which is exactly why
 * `sender.id === chrome.runtime.id` is not an internal check.
 */
export const pageSender = (origin = 'https://app.example') => ({
    id: EXT_ID,
    origin,
    url: `${origin}/some/page`,
});

/** Another extension, or anything not carrying our id. */
export const foreignSender = (origin = 'https://evil.example') => ({
    id: 'some-other-extension-id',
    origin,
    url: `${origin}/page`,
});
