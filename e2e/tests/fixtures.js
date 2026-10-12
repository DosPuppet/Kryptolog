// Two people, two browsers.
//
//   alice — Chromium with TrustKeys loaded unpacked: custody in the extension,
//           every signature and decryption through its approval windows.
//   bob   — a plain Chromium with a local vault: custody in the SPA itself.
//
// Between them they cover both custody paths against one real server, which is
// the seam no unit test reaches.
import { test as base, chromium, expect } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const EXTENSION = path.resolve(here, '../../trustkeys/dist');
export const PASSWORD = 'correct horse battery staple';

/**
 * Click through every TrustKeys approval window, and remember what it showed.
 * Approving blindly would prove nothing about the windows themselves, so each
 * window's text is kept and the specs assert on it.
 */
const autoApprove = (context, extensionId, shown) => {
    context.on('page', async (page) => {
        try {
            await page.waitForLoadState('domcontentloaded');
            if (!page.url().startsWith(`chrome-extension://${extensionId}/`)) return;
            const button = page.locator('button.primary');
            await button.waitFor({ timeout: 15_000 });
            shown.push(await page.locator('body').innerText());
            await button.click();
        } catch {
            // The window closed itself, or was not an approval: nothing to do.
        }
    });
};

export const test = base.extend({
    alice: async ({}, use) => {
        const context = await chromium.launchPersistentContext('', {
            channel: 'chromium',
            args: [`--disable-extensions-except=${EXTENSION}`, `--load-extension=${EXTENSION}`],
        });
        let [worker] = context.serviceWorkers();
        if (!worker) worker = await context.waitForEvent('serviceworker');
        const extensionId = new URL(worker.url()).host;
        const approvals = [];
        await use({ context, extensionId, approvals, page: await context.newPage() });
        await context.close();
    },
    bob: async ({}, use) => {
        const context = await chromium.launchPersistentContext('', { channel: 'chromium' });
        await use({ context, page: await context.newPage() });
        await context.close();
    },
});

export { expect, autoApprove };
