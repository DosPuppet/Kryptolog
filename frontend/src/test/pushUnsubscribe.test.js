/**
 * A push endpoint never travels in a query string (audit 2026-09-11 F-8).
 *
 * The endpoint is a capability URL — whoever holds it can push to that
 * browser — and query strings end up in access logs and proxies. There were
 * two callers; the second was missed by the first pass at this, which is why
 * the scan below exists alongside the call.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { unsubscribeEndpoint } from '../context/NotificationContext';

const ENDPOINT = 'https://push.example/capability-secret';

beforeEach(() => {
    global.fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) }));
});

const sourceFiles = (dir) => readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === 'test' ? [] : sourceFiles(path);
    return /\.(js|jsx)$/.test(name) ? [path] : [];
});

describe('unsubscribing a push endpoint', () => {
    it('sends the endpoint in the body', async () => {
        await unsubscribeEndpoint(ENDPOINT, 'tok');
        const [url, init] = global.fetch.mock.calls[0];
        expect(String(url)).not.toContain('capability-secret');
        expect(String(url)).not.toContain('?');
        expect(JSON.parse(init.body)).toEqual({ endpoint: ENDPOINT });
    });

    it('is the only way the SPA unsubscribes', () => {
        const offenders = sourceFiles(join(__dirname, '..'))
            .filter((f) => /UNSUBSCRIBE\}?\s*`?\s*\?|\?endpoint=/.test(readFileSync(f, 'utf8')));
        expect(offenders).toEqual([]);
    });
});
