// An unauthenticated message is hidden until the reader asks (audit 2026-09-23 F-3).
//
// Verification gated adopting a session key, not displaying a message: text
// that decrypted under a cached key rendered in full beside a tiny "unverified"
// label — in a group, a member plus a colluding server could put words under
// someone else's name.
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import MessageBody from '../components/messenger/MessageBody';

const msg = (over) => ({ id: 1, plainText: 'transfer the funds', verified: true, ...over });
const body = (props) => render(<MessageBody isMe={false} suspicious={false} onDecrypt={vi.fn()} {...props} />);

describe('MessageBody', () => {
    it('shows a verified message', () => {
        body({ msg: msg() });
        expect(screen.getByText('transfer the funds')).toBeTruthy();
    });

    it('hides a message whose signature failed, until the reader asks', () => {
        body({ msg: msg({ verified: false }) });
        expect(screen.queryByText('transfer the funds')).toBeNull();
        expect(screen.getByText('Content hidden')).toBeTruthy();

        fireEvent.click(screen.getByText('Show it anyway'));
        expect(screen.getByText('transfer the funds')).toBeTruthy();
    });

    it('hides an unsigned message where the author has signed before', () => {
        body({ msg: msg({ verified: null }), suspicious: true });
        expect(screen.queryByText('transfer the funds')).toBeNull();
    });

    it('shows an unsigned message with no signed history (nothing was stripped)', () => {
        body({ msg: msg({ verified: null }), suspicious: false });
        expect(screen.getByText('transfer the funds')).toBeTruthy();
    });

    it('never hides the reader\'s own messages', () => {
        body({ msg: msg({ verified: false }), isMe: true });
        expect(screen.getByText('transfer the funds')).toBeTruthy();
    });

    it('says a redacted message was removed, and offers nothing to decrypt', () => {
        body({ msg: msg({ redacted: true, plainText: null }) });
        expect(screen.getByText('Content removed')).toBeTruthy();
        expect(screen.queryByText(/Decrypt/)).toBeNull();
    });
});
