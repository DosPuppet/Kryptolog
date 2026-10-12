// What each build's manifest lets pages do (audit 2026-09-11 F-6, Q-3).
import { describe, it, expect } from 'vitest';
import { manifestFor, NEVER_INJECTED } from '../manifest.config.js';

const allMatches = (m) => (m.content_scripts ?? []).flatMap((cs) => cs.matches);

describe('the shipped manifest', () => {
    it('production injects into no page statically', () => {
        const m = manifestFor('production');
        expect(m.content_scripts.length).toBeGreaterThan(0); // still built, still discoverable
        expect(allMatches(m)).toEqual(m.content_scripts.map(() => NEVER_INJECTED));
        expect(allMatches(m).some((p) => /localhost|127\.0\.0\.1/.test(p))).toBe(false);
    });

    it('development keeps localhost, which is what lets the SPA find it', () => {
        expect(allMatches(manifestFor('development'))).toContain('http://localhost/*');
    });

    it('no build lets a page address the extension directly', () => {
        for (const mode of ['production', 'development']) {
            expect(manifestFor(mode).externally_connectable).toBeUndefined();
        }
    });

    it('does not modify the source manifest it is built from', () => {
        manifestFor('production');
        expect(allMatches(manifestFor('development'))).toContain('http://localhost/*');
    });
});
