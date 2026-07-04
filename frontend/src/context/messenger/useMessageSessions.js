import { useState, useEffect, useRef } from 'react';
import { decryptWithSessionKey } from '../../utils/crypto';
import { verifyMessageAuthenticity } from './verifyMessage';

// Session-key state + the DM/group message decryption pipelines. Owns the
// sid → AES-key map and the per-conversation active-session ids; the caller
// (MessengerContext) supplies the custody-provider unwrap functions and the
// active-conversation state so manual decrypts can update the open chat.
export const useMessageSessions = ({
    user,
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
            delete updated[`group_${channelId}`];
            return updated;
        });
    };

    /**
     * Unified message processing: tries cached keys, batch-unwraps missing ones,
     * then re-decrypts. Works for both DMs (v1) and group messages (v2).
     *
     * @param {Array}  rawMsgs - Raw message objects from the API
     * @param {'dm'|'group'} mode - Protocol version to use
     */
    const processMessages = async (rawMsgs, mode = 'dm') => {
        const myAddr = user.address.toLowerCase();
        const version = mode === 'dm' ? 1 : 2;

        // Attach end-to-end signature verification (audit S1) before returning.
        // Verification is over the CIPHERTEXT, so it's independent of whether we
        // could decrypt — every message gets a verified flag in one pass.
        const finalize = (msgs) => Promise.all(msgs.map(async m => {
            let payload = m._sessionPayload;
            if (!payload) { try { payload = JSON.parse(m.content); } catch { payload = null; } }
            return { ...m, verified: await verifyMessageAuthenticity(m, payload, mode) };
        }));

        // 1. First pass: decrypt with cached keys, tag the rest with _sessionPayload
        const processed = await Promise.all(rawMsgs.map(async msg => {
            try {
                const payload = JSON.parse(msg.content);
                if (payload.v === version && payload.sid) {
                    if (sessionKeysRef.current[payload.sid]) {
                        const pt = await decryptWithSessionKey(payload.ct, sessionKeysRef.current[payload.sid]);
                        return { ...msg, plainText: pt };
                    }
                    return { ...msg, _sessionPayload: payload };
                }
            } catch { /* best-effort: failure is non-fatal */ }
            return { ...msg, plainText: null };
        }));

        // 2. Collect missing keys for batch unwrap
        const keysToUnwrap = {};
        for (const m of processed) {
            if (m._sessionPayload && !sessionKeysRef.current[m._sessionPayload.sid]) {
                const p = m._sessionPayload;
                if (p.keys) {
                    let keyBlob = null;
                    if (mode === 'dm') {
                        const isMeSender = m.sender_address.toLowerCase() === myAddr;
                        keyBlob = isMeSender ? p.keys.sender : p.keys.recip;
                    } else {
                        keyBlob = p.keys[myAddr];
                    }
                    if (keyBlob) keysToUnwrap[p.sid] = keyBlob;
                }
            }
        }

        // 3. Batch unwrap and re-decrypt
        const sids = Object.keys(keysToUnwrap);
        if (sids.length > 0) {
            const blobs = sids.map(sid => keysToUnwrap[sid]);
            try {
                const unwrappedList = await unwrapManySessionKeys(blobs);
                const newKeys = { ...sessionKeysRef.current };
                sids.forEach((sid, idx) => {
                    const k = unwrappedList[idx];
                    if (k) newKeys[sid] = k;
                });
                setSessionKeys(newKeys);

                // For DMs, track active session
                if (mode === 'dm') {
                    const recentMsg = processed.find(m => m._sessionPayload && sids.includes(m._sessionPayload.sid));
                    if (recentMsg) {
                        const pid = recentMsg.sender_address.toLowerCase() === myAddr
                            ? recentMsg.recipient_address.toLowerCase()
                            : recentMsg.sender_address.toLowerCase();
                        setActiveSessionIds(prev => ({ ...prev, [pid]: recentMsg._sessionPayload.sid }));
                    }
                }

                return await finalize(await Promise.all(processed.map(async m => {
                    if (m._sessionPayload && newKeys[m._sessionPayload.sid]) {
                        try {
                            const pt = await decryptWithSessionKey(m._sessionPayload.ct, newKeys[m._sessionPayload.sid]);
                            return { ...m, plainText: pt };
                        } catch { /* best-effort: failure is non-fatal */ }
                    }
                    return m;
                })));
            } catch (e) { console.error(`Batch unwrap failed (${mode})`, e); }
        } else if (mode === 'dm') {
            // Check if we already have a session ID active from cache
            const validMsg = processed.find(m => m.plainText && m._sessionPayload);
            if (validMsg) {
                const pid = validMsg.sender_address.toLowerCase() === myAddr
                    ? validMsg.recipient_address.toLowerCase()
                    : validMsg.sender_address.toLowerCase();
                setActiveSessionIds(prev => ({ ...prev, [pid]: validMsg._sessionPayload.sid }));
            }
        }

        return finalize(processed);
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

            const stateSetter = mode === 'dm' ? setActiveConversation : setActiveGroupConversation;
            const stateRef = mode === 'dm' ? activeConversationRef : activeGroupConversationRef;

            // If we already have the session key cached, decrypt just this message
            if (sessionKeysRef.current[payload.sid]) {
                const plainText = await decryptWithSessionKey(payload.ct, sessionKeysRef.current[payload.sid]);
                stateSetter(prev => ({
                    ...prev,
                    messages: prev.messages.map(m => m.id === msg.id ? { ...m, plainText } : m)
                }));
                return;
            }

            // Look up the key blob for this user
            let keyBlob = null;
            if (mode === 'dm' && payload.keys) {
                const isMeSender = msg.sender_address.toLowerCase() === user.address.toLowerCase();
                keyBlob = isMeSender ? payload.keys.sender : payload.keys.recip;
            } else if (mode === 'group' && payload.keys) {
                keyBlob = payload.keys[user.address.toLowerCase()];
            }

            if (!keyBlob) return;

            const sessionKey = await unwrapSessionKey(keyBlob);
            if (!sessionKey) return;

            setSessionKeys(prev => ({ ...prev, [payload.sid]: sessionKey }));

            // Re-decrypt ALL messages in the conversation sharing this session ID
            const currentMessages = stateRef.current?.messages || [];
            const resolvedMessages = await Promise.all(currentMessages.map(async m => {
                if (!m.plainText && m.content) {
                    try {
                        const p = JSON.parse(m.content);
                        if (p.v === version && p.sid === payload.sid) {
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
