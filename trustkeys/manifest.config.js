// The manifest each build ships (audit 2026-09-11 F-6).
//
// manifest.json declares two static content scripts on http://localhost and
// http://127.0.0.1. In a development build that is the point: the SPA on
// localhost:5173 gets window.trustkeys without being added as a trusted site.
// In a production build it meant every locally running application, on any
// port, received window.trustkeys and could open the connect prompt.
//
// The entries cannot simply be deleted from the production manifest. crxjs
// builds content scripts FROM them, and connection.js finds the built file
// names for trusted sites' dynamic registration by reading them back out of
// chrome.runtime.getManifest(). So production keeps the entries and points
// their `matches` at a reserved `.invalid` host (RFC 2606), which no page is
// ever served from: the files are built and discoverable, and injected only
// where the user granted a site.
//
// A cleaner route exists — import the scripts with crxjs's `?script&iife` and
// register them only dynamically — but it changes how the content scripts are
// bundled, and that needs a real browser to verify, which the test suite is not.

import base from './manifest.json' with { type: 'json' };

export const NEVER_INJECTED = 'https://trustkeys-static-scripts.invalid/*';

export const manifestFor = (mode) => {
    const manifest = structuredClone(base);
    if (mode === 'production') {
        for (const script of manifest.content_scripts ?? []) {
            script.matches = [NEVER_INJECTED];
        }
    }
    return manifest;
};
