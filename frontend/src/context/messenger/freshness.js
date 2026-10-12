// Replay, reordering and gap detection for verified messages (crypto-core 3.0.0,
// audit 2026-10-12 K-06).
//
// A signature proves who wrote a message, not WHEN it was delivered or whether
// it was delivered once. The server sets `created_at` and decides the order, so
// before 3.0.0 it could re-deliver an old message as new, drop one, or swap two,
// and every copy still showed "verified". Each message now signs its sender's
// clock (`ts`) and its position in the session (`seq`), and a session has
// exactly one sender — a client only ever encrypts under a session it minted
// itself — so (conversation, sid, sender) with a seq is a sequence the receiver
// can hold the server to.
//
// What is detected, in the order it is reported:
//   'replayed'  — a (session, seq) already seen under a different message id.
//   'skew'      — the signed ts is far from the server's delivery time. An old
//                 message re-delivered as a new row lands here: its ts is old.
//   'reordered' — a seq at or below one already delivered LATER in time.
//   'gap'       — seqs skip forward, so something in between never arrived.
//
// Order and gaps are judged only for messages newer than everything already
// seen in that session: loading older history arrives backwards by design, and
// a page boundary is not a missing message.

// Generous on purpose: device clocks drift, and a phone can sit offline with a
// message queued. A re-delivered message is typically far older than this.
export const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;

const isCount = (n) => Number.isSafeInteger(n) && n >= 0;

/**
 * Mark each verified message with a freshness verdict.
 *
 * `messages`: chronological, each with `id`, `created_at`, `sender_address`,
 *   `verified`, and `_sessionPayload` ({ sid, ts, seq } or null).
 * `seen`: a mutable object owned by the caller (a ref), carrying what earlier
 *   calls observed, so a live message is judged against loaded history.
 * `conversationOf(msg)`: the conversation scope, as sessionScope.js derives it.
 *
 * Returns a Map of message id -> verdict; messages that are fine are omitted.
 */
export const assessFreshness = (messages, seen, conversationOf) => {
    const verdicts = new Map();
    for (const msg of messages) {
        const p = msg._sessionPayload;
        if (msg.verified !== true || !p || !isCount(p.ts) || !isCount(p.seq)) continue;

        const key = `${conversationOf(msg)}:${p.sid}:${(msg.sender_address || '').toLowerCase()}`;
        const at = Date.parse(msg.created_at);
        const state = (seen[key] ??= { ids: new Map(), maxSeq: -1, maxAt: -Infinity });

        const firstId = state.ids.get(p.seq);
        if (firstId !== undefined && firstId !== msg.id) {
            verdicts.set(msg.id, 'replayed');
            continue;
        }
        state.ids.set(p.seq, msg.id);

        if (Number.isFinite(at) && Math.abs(p.ts - at) > MAX_CLOCK_SKEW_MS) {
            verdicts.set(msg.id, 'skew');
        }

        if (Number.isFinite(at) && at >= state.maxAt) {
            if (state.maxSeq >= 0 && p.seq <= state.maxSeq && firstId === undefined) {
                verdicts.set(msg.id, verdicts.get(msg.id) ?? 'reordered');
            } else if (state.maxSeq >= 0 && p.seq > state.maxSeq + 1) {
                verdicts.set(msg.id, verdicts.get(msg.id) ?? 'gap');
            }
            if (p.seq > state.maxSeq) state.maxSeq = p.seq;
            state.maxAt = at;
        }
    }
    return verdicts;
};
