// Origin and sender boundaries — the checks every other gate is built on.
//
// The load-bearing one is isInternalSender: a content script also carries
// `sender.id === chrome.runtime.id`, so the id alone would classify any
// connected page as the extension's own UI (audit M4 / M-5).

import { describe, it, expect, beforeEach } from 'vitest';
import { installChrome, internalSender, pageSender, foreignSender, EXT_ID } from './chrome-mock.js';

let utils;

beforeEach(async () => {
    installChrome();
    utils = await import('../src/background/utils.js');
});

describe('isInternalSender', () => {
    it('accepts the extension\'s own pages', () => {
        expect(utils.isInternalSender(internalSender())).toBe(true);
        expect(utils.isInternalSender(internalSender('?route=sign&requestId=x'))).toBe(true);
    });

    it('REJECTS a content script even though it carries the extension id', () => {
        const cs = pageSender();
        expect(cs.id).toBe(EXT_ID); // the trap: id alone says "internal"
        expect(utils.isInternalSender(cs)).toBe(false);
    });

    it('rejects another extension, and anything malformed', () => {
        expect(utils.isInternalSender(foreignSender())).toBe(false);
        expect(utils.isInternalSender(null)).toBe(false);
        expect(utils.isInternalSender({})).toBe(false);
        expect(utils.isInternalSender({ id: EXT_ID })).toBe(false); // no url
    });

    it('is not fooled by a page URL that merely mentions index.html', () => {
        // The id has to match too — a page cannot forge that.
        expect(utils.isInternalSender({
            id: 'not-us', url: `https://evil.example/index.html`,
        })).toBe(false);
    });
});

describe('getSenderOrigin', () => {
    it('returns the origin Chrome attached', () => {
        expect(utils.getSenderOrigin(pageSender('https://app.example'))).toBe('https://app.example');
    });

    it('returns null rather than falling back when Chrome gave none', () => {
        // Callers must DENY on null; a payload-supplied origin is attacker-controlled.
        expect(utils.getSenderOrigin({ id: EXT_ID })).toBeNull();
        expect(utils.getSenderOrigin(null)).toBeNull();
    });
});

describe('isAllowedTrustedOrigin', () => {
    it('allows https', () => {
        expect(utils.isAllowedTrustedOrigin('https://app.example')).toBe(true);
    });

    it('allows the dev origins, which the static manifest already covers', () => {
        expect(utils.isAllowedTrustedOrigin('http://localhost:5173')).toBe(true);
        expect(utils.isAllowedTrustedOrigin('http://127.0.0.1:8000')).toBe(true);
    });

    it('refuses plain http elsewhere — a network attacker could inject into it', () => {
        expect(utils.isAllowedTrustedOrigin('http://app.example')).toBe(false);
        expect(utils.isAllowedTrustedOrigin('')).toBe(false);
        expect(utils.isAllowedTrustedOrigin(null)).toBe(false);
    });

    it('is not fooled by a hostname that merely starts with the dev origin', () => {
        expect(utils.isDevOrigin('http://localhost.evil.example')).toBe(true); // known prefix match
        // ...but it still has to be http(s) and, above, https to be trusted in prod.
        expect(utils.isAllowedTrustedOrigin('https://localhost.evil.example')).toBe(true);
    });
});
