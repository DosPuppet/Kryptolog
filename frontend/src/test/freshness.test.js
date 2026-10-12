// Replay / reorder / gap detection (crypto-core 3.0.0, audit 2026-10-12 K-06).
//
// A server cannot forge a signed message, but before 3.0.0 it could deliver one
// twice, hold one back, or swap two, and every copy still showed "verified".
// These pin what each of those looks like to the receiver, and — just as
// important — what must NOT be flagged: loading older history arrives
// backwards, and a page boundary is not a missing message.

import { describe, it, expect } from 'vitest';
import { assessFreshness, MAX_CLOCK_SKEW_MS } from '../context/messenger/freshness';

const T0 = Date.parse('2026-10-12T10:00:00Z');
const ALICE = 'aa11';

const msg = (id, seq, { at = T0 + seq * 1000, ts = at, sid = 'S', from = ALICE, verified = true } = {}) => ({
    id,
    sender_address: from,
    created_at: new Date(at).toISOString(),
    verified,
    _sessionPayload: { sid, ts, seq },
});

const run = (batches) => {
    const seen = {};
    return batches.map((batch) => assessFreshness(batch, seen, () => 'conv'));
};

describe('assessFreshness', () => {
    it('says nothing about an ordinary conversation', () => {
        const [v] = run([[msg(1, 0), msg(2, 1), msg(3, 2)]]);
        expect(v.size).toBe(0);
    });

    it('flags a replay: the same position delivered again as a new message', () => {
        const [, v] = run([[msg(1, 0), msg(2, 1)], [msg(9, 1, { at: T0 + 5000 })]]);
        expect(v.get(9)).toBe('replayed');
    });

    it('does not flag the same message seen twice (a refetch is not a replay)', () => {
        const [, v] = run([[msg(1, 0), msg(2, 1)], [msg(2, 1)]]);
        expect(v.size).toBe(0);
    });

    it('flags an old message re-delivered as new: its signed clock is far from delivery', () => {
        const old = T0 - 3 * 24 * 3600 * 1000;
        const [v] = run([[msg(1, 0, { ts: old, at: T0 })]]);
        expect(v.get(1)).toBe('skew');
    });

    it('tolerates ordinary clock drift', () => {
        const [v] = run([[msg(1, 0, { ts: T0 - MAX_CLOCK_SKEW_MS / 2, at: T0 })]]);
        expect(v.size).toBe(0);
    });

    it('flags a gap: a later position arrives with the one before it missing', () => {
        const [v] = run([[msg(1, 0), msg(2, 1), msg(3, 3)]]);
        expect(v.get(3)).toBe('gap');
    });

    it('flags a reordering: a position delivered after a later one', () => {
        const [, v] = run([[msg(1, 0), msg(3, 2)], [msg(2, 1, { at: T0 + 10_000 })]]);
        expect(v.get(2)).toBe('reordered');
    });

    it('does not mistake older history, loaded afterwards, for a reordering or a gap', () => {
        // The newest page first, then "load more": the older page arrives
        // after, with lower seqs and earlier delivery times. That is the
        // normal shape of paging, not an attack.
        const [newest, older] = run([[msg(5, 5), msg(6, 6)], [msg(1, 1), msg(2, 2)]]);
        expect(newest.size).toBe(0);
        expect(older.size).toBe(0);
    });

    it('scopes positions per session and per sender', () => {
        const [v] = run([[
            msg(1, 0, { sid: 'S1' }), msg(2, 0, { sid: 'S2', at: T0 + 1 }),
            msg(3, 0, { from: 'bb22', at: T0 + 2 }),
        ]]);
        expect(v.size).toBe(0);
    });

    it('judges only verified messages: an unverified one already says so', () => {
        const [v] = run([[msg(1, 0), msg(2, 0, { verified: false, at: T0 + 5 })]]);
        expect(v.size).toBe(0);
    });
});
