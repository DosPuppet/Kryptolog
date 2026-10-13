import { useState, useEffect, useRef } from 'react';
import { decryptWithSessionKey } from '../../utils/crypto';
import { verifyMessageAuthenticity } from './verifyMessage';
import { sessionKeyId, groupConversationId, conversationIdForMessage, mayAdoptSession } from './sessionScope';
import { assessFreshness } from './freshness';

// Session-key state + the DM/group message decryption pipelines. Owns the
// (conversation, sid) → AES-key map and the per-conversation active-session
// ids; the caller (MessengerContext) supplies the custody-provider unwrap
// functions and the active-conversation state so manual decrypts can update
// the open chat.
export const useMessageSessions = ({
    user,
    token,
    unwrapSessionKey,
    unwrapManySessionKeys,
    activeConversationRef,
    setActiveConversation,
    activeGroupConversationRef,
    setActiveGroupConversation,
}) => {
    const [sessionKeys, setSessionKeys] = useState({});
    const sessionKeysRef = useRef({});
    useEffect(() => { sessionKeysRef.current = sessionKeys; }, [sessionKeys]);

    const [activeSessionIds, setActiveSessionIds] = useState({});

    // What each (conversation, session, sender) has delivered so far, so a
    // live message is judged against loaded history (messenger/freshness.js).
    const freshnessSeenRef = useRef({});

    // Group key rotation & forward secrecy (audit S2).
    //
    // A group message wraps a fresh AES session key (sid) for each member's
    // ML-KEM key, embedded in the first message under that sid; later messages
    // reuse the sid. On any membership change we DROP the active sid so the next
    // send mints a new one wrapped for the *current* member set:
    //   • removed member → not in the new wrap, so they cannot read future
    //     messages (forward secrecy). The server also stops delivering the
    //     channel to non-members, so this is defense-in-depth.
    //   • added member → included in the new wrap, so they can read from the
    //     next message on, but NOT prior history (they were never wrapped for the
    //     old sid) — which is the desired property.
    // Invalidation runs both for the actor (add/removeGroupMember) and for every
    // other member via the GROUP_MEMBER_ADDED/REMOVED WS events, so each client
    // rekeys independently before its next send.
    //
    // Not provided: post-compromise security / per-message ratcheting — a leaked
    // session key exposes messages under that sid until the next rotation.
    const invalidateGroupSession = (channelId) => {
        setActiveSessionIds(prev => {
            const updated = { ...prev };
            delete updated[groupConversationId(channelId)];
            return updated;
        });
    };

    /**
     * Unified message processing: verifies, tries cached keys, batch-unwraps the
     * missing ones it is allowed to adopt, then re-decrypts. Works for both DMs
     * (v1) and group messages (v2).
     *
     * @param {Array}  rawMsgs - Raw message objects from the API
     * @param {'dm'|'group'} mode - Protocol version to use
     */
    const processMessages = async (rawMsgs, mode = 'dm') => {
        const myAddr = user.address.toLowerCase();
        const version = mode === 'dm' ? 1 : 2;
        const convOf = (msg) => conversationIdForMessage(msg, myAddr, mode);

        // 1. Parse and VERIFY — before anything is adopted (audit H-1).
        //
        // Verification used to run last, in a `finalize` pass that only tagged
        // the returned objects with a `verified` flag for the UI badge. By then
        // the session key had already been adopted, so the signature gated
        // nothing. It runs first now; see mayAdoptSession in sessionScope.js
        // for what it gates.
        //
        // Verification is over the CIPHERTEXT and the server-attested delivery
        // context, so every message gets a flag whether or not we can decrypt.
        const prepared = await Promise.all(rawMsgs.map(async msg => {
            let parsed = null;
            try { parsed = JSON.parse(msg.content); } catch { /* legacy/plain content */ }
            const verified = await verifyMessageAuthenticity(msg, parsed, mode, token);
            const payload = parsed && parsed.v === version && parsed.sid ? parsed : null;
            // Content the author removed on their way out of the app: the key
            // envelope survives (other people's messages in this session depend
            // on it) and the signature still verifies, because the author signed
            // this exact form. So it stays adoptable — it just has nothing to
            // decrypt, and must never offer a decrypt button that can only fail.
            const redacted = !!payload && payload.ct == null;
            return { ...msg, verified, redacted, plainText: null, _sessionPayload: payload };
        }));

        // Replay / reorder / gap (crypto-core 3.0.0, audit 2026-10-12 K-06).
        // Judged on verified messages only: the signature is what makes ts and
        // seq the author's statement rather than the server's.
        const freshness = assessFreshness(prepared, freshnessSeenRef.current, convOf);
        for (const m of prepared) {
            if (freshness.has(m.id)) m.freshness = freshness.get(m.id);
        }

        // 2. Decrypt whatever the cache already covers.
        const processed = await Promise.all(prepared.map(async m => {
            const p = m._sessionPayload;
            if (!p) return m;
            const key = sessionKeysRef.current[sessionKeyId(convOf(m), p.sid)];
            if (!key || m.redacted) return m;
            try {
                return { ...m, plainText: await decryptWithSessionKey(p.ct, key) };
            } catch { return m; /* best-effort: failure is non-fatal */ }
        }));

        // 3. Collect the still-missing keys, from messages allowed to seed the
        //    cache. Keyed by (conversation, sid): a session adopted here is
        //    unreachable from any other conversation.
        const keysToUnwrap = {};
        for (const m of processed) {
            const p = m._sessionPayload;
            if (!p || !p.keys) continue;
            const keyId = sessionKeyId(convOf(m), p.sid);
            if (sessionKeysRef.current[keyId] || keysToUnwrap[keyId]) continue;
            if (!mayAdoptSession(m, m.verified, mode, myAddr)) continue;
            const keyBlob = mode === 'dm'
                ? (m.sender_address.toLowerCase() === myAddr ? p.keys.sender : p.keys.recip)
                : p.keys[myAddr];
            if (keyBlob) keysToUnwrap[keyId] = keyBlob;
        }

        const keyIds = Object.keys(keysToUnwrap);

        if (keyIds.length === 0) {
            return processed;
        }

        // 4. Batch unwrap, then re-decrypt what the new keys unlock.
        try {
            const unwrappedList = await unwrapManySessionKeys(keyIds.map(id => keysToUnwrap[id]));
            const newKeys = { ...sessionKeysRef.current };
            keyIds.forEach((id, idx) => {
                const k = unwrappedList[idx];
                if (k) newKeys[id] = k;
            });
            setSessionKeys(newKeys);

            // Neither DMs nor groups adopt a SEND key from inbound history: an
            // adopted key DECRYPTS and never ENCRYPTS. Do not "fix" this.
            //
            // Groups never did (audit O-1). mayAdoptSession cannot check
            // membership — the hook has no member list, and the one it could
            // be handed comes from the server, which is the adversary. A
            // verified message proves the sender holds the key for the address
            // it claims, NOT that the address belongs in the channel, so a
            // server could mint an identity, sign correctly, and wrap keys[me]
            // to a key it owns. As a send key, that is H-1 in a group.
            //
            // DMs did until crypto-core 3.0.0: the next send reused the
            // partner's newest session. A session now has exactly one sender —
            // whoever minted it, on this page load — because that is what makes
            // its `seq` a sequence the receiver can hold the server to (audit
            // 2026-10-12 K-06), and minting per page load plus rotation bounds
            // what one leaked session key exposes (K-07). The cost is two
            // ML-KEM wraps on the first DM after a page load.
            return await Promise.all(processed.map(async m => {
                const p = m._sessionPayload;
                if (!p || m.plainText !== null) return m;
                const key = newKeys[sessionKeyId(convOf(m), p.sid)];
                if (!key || m.redacted) return m;
                try {
                    return { ...m, plainText: await decryptWithSessionKey(p.ct, key) };
                } catch { return m; /* best-effort: failure is non-fatal */ }
            }));
        } catch (e) {
            console.error(`Batch unwrap failed (${mode})`, e);
            return processed;
        }
    };

    /**
     * Unified manual decryption handler for both DMs and group messages.
     * When a key is unwrapped, it re-decrypts all sibling messages in the same session.
     *
     * @param {Object} msg - The message to decrypt
     * @param {'dm'|'group'} mode - Protocol version
     */
    const handleManualDecrypt = async (msg, mode = 'dm') => {
        try {
            const payload = JSON.parse(msg.content);
            const version = mode === 'dm' ? 1 : 2;
            if (payload.v !== version || !payload.sid) return;

            const myAddr = user.address.toLowerCase();
            const convOf = (m) => conversationIdForMessage(m, myAddr, mode);
            const keyId = sessionKeyId(convOf(msg), payload.sid);

            const stateSetter = mode === 'dm' ? setActiveConversation : setActiveGroupConversation;
            const stateRef = mode === 'dm' ? activeConversationRef : activeGroupConversationRef;

            // Cached key: decrypt just this message. Nothing is adopted here, so
            // no gate applies — the key was vetted when it entered the cache.
            if (sessionKeysRef.current[keyId]) {
                const plainText = await decryptWithSessionKey(payload.ct, sessionKeysRef.current[keyId]);
                stateSetter(prev => ({
                    ...prev,
                    messages: prev.messages.map(m => m.id === msg.id ? { ...m, plainText } : m)
                }));
                return;
            }

            // Unwrapping a new key from this message IS an adoption, so it takes
            // the same gate as processMessages (audit H-1) — otherwise the
            // "decrypt" button in the UI is the way around it.
            const verified = await verifyMessageAuthenticity(msg, payload, mode, token);
            if (!mayAdoptSession(msg, verified, mode, myAddr)) return;

            // Look up the key blob for this user
            let keyBlob = null;
            if (mode === 'dm' && payload.keys) {
                const isMeSender = msg.sender_address.toLowerCase() === myAddr;
                keyBlob = isMeSender ? payload.keys.sender : payload.keys.recip;
            } else if (mode === 'group' && payload.keys) {
                keyBlob = payload.keys[myAddr];
            }

            if (!keyBlob) return;

            const sessionKey = await unwrapSessionKey(keyBlob);
            if (!sessionKey) return;

            setSessionKeys(prev => ({ ...prev, [keyId]: sessionKey }));

            // Re-decrypt every sibling message sharing this (conversation, sid).
            const currentMessages = stateRef.current?.messages || [];
            const resolvedMessages = await Promise.all(currentMessages.map(async m => {
                if (!m.plainText && m.content) {
                    try {
                        const p = JSON.parse(m.content);
                        if (p.v === version && p.sid && sessionKeyId(convOf(m), p.sid) === keyId) {
                            const pt = await decryptWithSessionKey(p.ct, sessionKey);
                            return { ...m, plainText: pt };
                        }
                    } catch { /* best-effort: failure is non-fatal */ }
                }
                return m;
            }));

            stateSetter(prev => ({ ...prev, messages: resolvedMessages }));
        } catch (e) { console.error(`Manual decrypt failed (${mode})`, e); }
    };

    return {
        sessionKeys,
        sessionKeysRef,
        setSessionKeys,
        activeSessionIds,
        setActiveSessionIds,
        invalidateGroupSession,
        processMessages,
        handleManualDecrypt,
    };
};
