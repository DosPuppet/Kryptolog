import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import MessageAuthBadge from '../components/messenger/MessageAuthBadge';

// Audit F-2: an unsigned message must never render silently (pre-fix it showed
// nothing, so a server could strip signatures undetected). It now always shows
// an indicator, escalating to a red warning when the conversation has signed
// history (a likely signature-stripping attack rather than a legacy client).
describe('MessageAuthBadge (F-2)', () => {
    it('shows a neutral "unsigned" indicator when there is no signed history', () => {
        render(<MessageAuthBadge verified={null} suspicious={false} />);
        const span = screen.getByText('unsigned').closest('span');
        expect(span).toBeInTheDocument();
        expect(span.getAttribute('title')).toMatch(/could not be cryptographically verified/i);
        expect(span.className).toMatch(/text-amber-500/);
    });

    it('escalates to a red suspicious warning when the conversation has signed history', () => {
        render(<MessageAuthBadge verified={null} suspicious={true} />);
        const span = screen.getByText('unsigned').closest('span');
        expect(span.getAttribute('title')).toMatch(/may have been tampered with/i);
        expect(span.className).toMatch(/text-red-500/);
    });

    it('treats undefined like null (still surfaces an unsigned indicator)', () => {
        render(<MessageAuthBadge verified={undefined} />);
        expect(screen.getByText('unsigned')).toBeInTheDocument();
    });

    it('shows "unverified" for a present-but-invalid signature', () => {
        render(<MessageAuthBadge verified={false} />);
        expect(screen.getByText('unverified')).toBeInTheDocument();
    });

    it('renders no unsigned/unverified text for a verified message', () => {
        render(<MessageAuthBadge verified={true} />);
        expect(screen.queryByText('unsigned')).toBeNull();
        expect(screen.queryByText('unverified')).toBeNull();
    });
});
