// Conversation scoping and the session-adoption rule (audit H-1).
//
// Session keys used to be cached under the bare `sid`, a single global
// namespace. The sid is chosen by whoever composed the message, so it is not a
// namespace this client controls: a key that landed in the cache from ANY
// conversation was reachable from every other one. Scoping every read and
// write by conversation means a session can only ever be used where it was
// delivered.
//
// `conv` is the same string `activeSessionIds` is keyed by — the partner's
// lowercased address for DMs, `group_<channelId>` for group channels — so the
// two maps stay in step.

export const sessionKeyId = (conv, sid) => `${conv}:${sid}`;

export const dmConversationId = (address) => (address || '').toLowerCase();

export const groupConversationId = (channelId) => `group_${channelId}`;

// The conversation a delivered message belongs to. Derived from the message
// ROW — the server-attested delivery context — never from fields inside the
// content payload, which is the same rule the signature binding follows
// (audit F-1). A server that re-homes a message therefore changes the scope it
// lands in rather than smuggling a key across conversations.
export const conversationIdForMessage = (msg, myAddress, mode) => {
    if (mode === 'group') return groupConversationId(msg.channel_id);
    const from = dmConversationId(msg.sender_address);
    return from === dmConversationId(myAddress)
        ? dmConversationId(msg.recipient_address)
        : from;
};

// May this message SEED the session-key cache? (audit H-1)
//
// This is the gate the whole finding turns on. Signature verification used to
// run last and only decorate the message with a `verified` flag for the UI
// badge — the key was already adopted by then. So a server could inject a
// message carrying a `keys` block IT could unwrap, we would adopt that key as
// the conversation's active session, and the next outbound message went out
// encrypted to a key the server holds. Verification has to gate adoption, not
// describe it after the fact.
//
// `verified === true` strictly: `null` means unsigned, and an unsigned message
// proves nothing about who composed it. That makes legacy unsigned sessions
// unreadable, which is deliberate — accepting them keeps the bypass open, and
// the project's stance on wire-format changes is a clean cutover rather than a
// fallback that doubles as a downgrade path.
export const mayAdoptSession = (msg, verified, mode, myAddress) => {
    if (verified !== true) return false;
    const from = dmConversationId(msg.sender_address);
    if (mode === 'group') {
        // The signature binds `conv` to the row's channel_id, so a verified
        // group message was signed for THIS channel by whoever holds that
        // address. Membership is not re-checked here: the hook has no member
        // list, and group sessions are never adopted as the SEND key (see the
        // O-1 note in useMessageSessions), so an adopted group key can only
        // ever decrypt, never encrypt.
        return Boolean(from);
    }
    // DM: one end of the message has to be us. Checking "sender is the
    // partner" would be vacuous — the partner is DERIVED from the sender — so
    // the real invariant is that the message belongs to a conversation we are
    // actually in. A message between two other parties, injected into our
    // history, scopes to a conversation we never opened and seeds nothing.
    const me = dmConversationId(myAddress);
    return from === me || dmConversationId(msg.recipient_address) === me;
};
