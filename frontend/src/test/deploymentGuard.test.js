/**
 * A production bundle built without its configuration builds cleanly and
 * fails in users' browsers (found by a real install, 2026-10-15): no
 * VITE_API_BASE_URL means every user's SPA calls their own localhost:8000.
 * The guard says so at build time, and refuses in strict mode — the mode
 * scripts/deploy_frontend.sh builds in.
 */
import { describe, it, expect, vi } from 'vitest';
import { deploymentProblems, deploymentGuard } from '../../deploymentGuard.js';

const VAPID = 'B' + 'A'.repeat(86);
const GOOD = { VITE_API_BASE_URL: 'https://kryptolog.example.com/api', VITE_VAPID_PUBLIC_KEY: VAPID };
const fatal = (env) => deploymentProblems(env).filter(p => p.fatal).map(p => p.message);

describe('deploymentProblems', () => {
    it('passes a public https API and a well-formed VAPID key', () => {
        expect(deploymentProblems(GOOD)).toEqual([]);
    });

    it.each([
        [undefined, /unset/],
        ['', /unset/],
        ['http://localhost:8000', /loopback/],
        ['https://127.0.0.1/api', /loopback/],
        ['https://[::1]:8000', /loopback/],
        ['https://app.localhost/api', /loopback/],
        ['http://kryptolog.example.com/api', /plain http/],
        ['kryptolog.example.com/api', /not a URL/],
    ])('refuses VITE_API_BASE_URL=%s', (api, reason) => {
        expect(fatal({ ...GOOD, VITE_API_BASE_URL: api })).toEqual([expect.stringMatching(reason)]);
    });

    it('treats a missing VAPID key as a warning, since push is optional', () => {
        const problems = deploymentProblems({ ...GOOD, VITE_VAPID_PUBLIC_KEY: '' });
        expect(problems).toEqual([{ fatal: false, message: expect.stringMatching(/push notifications are off/) }]);
    });

    it.each([
        ['the PEM-ish value people paste', 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE'],
        ['a compressed point', 'A' + 'A'.repeat(43)],
        ['standard base64', 'B' + '+'.repeat(86)],
    ])('refuses a VAPID key that is %s', (_, key) => {
        expect(fatal({ ...GOOD, VITE_VAPID_PUBLIC_KEY: key })).toEqual([expect.stringMatching(/P-256/)]);
    });
});

describe('the plugin', () => {
    const run = (env) => {
        const plugin = deploymentGuard(env);
        const ctx = { error: vi.fn((msg) => { throw new Error(msg); }) };
        return () => plugin.buildStart.call(ctx);
    };

    it('only applies to builds', () => {
        expect(deploymentGuard(GOOD).apply).toBe('build');
    });

    it('refuses an undeployable bundle in strict mode', () => {
        expect(run({ KRYPTOLOG_STRICT_BUILD: '1' })).toThrow(/not deployable[\s\S]*VITE_API_BASE_URL is unset/);
    });

    it('builds it anyway outside strict mode, loudly', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        expect(run({})).not.toThrow();
        expect(warn).toHaveBeenCalledWith(expect.stringMatching(/NOT A DEPLOYABLE BUNDLE/));
        warn.mockRestore();
    });

    it('does not fail a strict build over push being off', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        expect(run({ ...GOOD, VITE_VAPID_PUBLIC_KEY: '', KRYPTOLOG_STRICT_BUILD: '1' })).not.toThrow();
        warn.mockRestore();
    });
});
