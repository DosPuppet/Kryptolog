import { describe, it, expect } from 'vitest';
import {
    formatSize,
    shortAddress,
    middleEllipsis,
    displayName,
    avatarInitial,
} from '../utils/format';

describe('formatSize', () => {
    it('scales through B, KB and MB', () => {
        expect(formatSize(512)).toBe('512 B');
        expect(formatSize(2048)).toBe('2.0 KB');
        expect(formatSize(5 * 1024 * 1024)).toBe('5.0 MB');
    });

    it('renders nothing for an absent or zero size', () => {
        // Callers interpolate this straight into a label, so "0 B" would put a
        // meaningless suffix next to files whose size we do not know.
        expect(formatSize(0)).toBe('');
        expect(formatSize(undefined)).toBe('');
    });
});

describe('address labels', () => {
    const addr = 'a'.repeat(40) + 'b'.repeat(40);

    it('truncates from the front by default', () => {
        expect(shortAddress(addr)).toBe('aaaaaaaa...');
        expect(shortAddress(addr, 4)).toBe('aaaa...');
        expect(shortAddress(null)).toBe('');
    });

    it('keeps both ends only where asked', () => {
        expect(middleEllipsis(addr)).toBe('aaaaaaaa...bbbbbbbb');
        expect(middleEllipsis('short')).toBe('short');
        expect(middleEllipsis(null)).toBe('');
    });

    it('prefers a username and falls back to the address', () => {
        expect(displayName({ username: 'alice', address: addr })).toBe('alice');
        expect(displayName({ address: addr })).toBe('aaaaaaaa...');
        expect(displayName(null)).toBe('');
    });

    it('reads user_address too, which the group member rows use', () => {
        expect(displayName({ user_address: addr })).toBe('aaaaaaaa...');
    });

    it('gives an avatar letter, never an empty bubble', () => {
        expect(avatarInitial('alice')).toBe('A');
        expect(avatarInitial('')).toBe('?');
        expect(avatarInitial(undefined)).toBe('?');
    });
});
