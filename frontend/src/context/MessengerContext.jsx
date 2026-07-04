import { createContext, useContext, useState, useEffect, useRef, useMemo } from 'react';
import { useAuth } from './AuthContext';
import { usePQC } from './PQCContext';
import API_ENDPOINTS from '../config';
import { encryptWithSessionKey, decryptWithSessionKey, messageSigningBody } from '../utils/crypto';
import { isEncryptedTitle, LOCKED_TITLE } from '../utils/titles';
import { assertSafeRecipient, attestationStatus } from '../services/trustedKeys';
import { toast } from '../utils/toast';
import { verifyMessageAuthenticity } from './messenger/verifyMessage';
import { useMessengerSocket } from './messenger/useMessengerSocket';
import { useMessageSessions } from './messenger/useMessageSessions';
import { useGroupNames } from './messenger/useGroupNames';
import { createGroupEventHandlers } from './messenger/groupEvents';

// Re-exported for existing importers (tests); the implementation lives in
// messenger/verifyMessage.js.
export { verifyMessageAuthenticity };

const MessengerContext = createContext();

export const useMessengerContext = () => {
    const context = useContext(MessengerContext);
    if (!context) {
        throw new Error('useMessengerContext must be used within a MessengerProvider');
    }
    return context;
};

export const MessengerProvider = ({ children }) => {
    const { user, token } = useAuth();
    const { generateSessionKey, wrapSessionKey, unwrapSessionKey, unwrapManySessionKeys, mlkemKey, signMessage } = usePQC();

    const [conversations, setConversations] = useState([]);
    const [activeConversation, setActiveConversation] = useState(null); // { user, messages: [] }
    const activeConversationRef = useRef(null);
    useEffect(() => { activeConversationRef.current = activeConversation; }, [activeConversation]);

    const [loading, setLoading] = useState(true);
    const [messagesLoading, setMessagesLoading] = useState(false);
    const [sending, setSending] = useState(false);

    // ── Group Channels State ───────────────────────────────────────
    const [groupConversations, setGroupConversations] = useState([]);
    const [activeGroupConversation, setActiveGroupConversation] = useState(null);
    const activeGroupConversationRef = useRef(null);
    useEffect(() => { activeGroupConversationRef.current = activeGroupConversation; }, [activeGroupConversation]);

    // Event Listeners (e.g. for Dashboard to refresh secrets)
    const [lastEvent, setLastEvent] = useState(null);

    // Session-key state + decryption pipelines (messenger/useMessageSessions.js)
    const {
        sessionKeys,
        sessionKeysRef,
        setSessionKeys,
        activeSessionIds,
        setActiveSessionIds,
        invalidateGroupSession,
        processMessages,
        handleManualDecrypt,
    } = useMessageSessions({
        user,
        unwrapSessionKey,
        unwrapManySessionKeys,
        activeConversationRef,
        setActiveConversation,
        activeGroupConversationRef,
        setActiveGroupConversation,
    });

    // Encrypted group names, audit M-3 (messenger/useGroupNames.js)
    const { resolveChannelName, resolveGroupNames, buildGroupNameBlob } =
        useGroupNames({ user, mlkemKey, unwrapManySessionKeys });

    // ── Shared Helpers ─────────────────────────────────────────────

    /** Authenticated API call — handles headers, JSON parsing, and error throwing. */
    const api = async (url, options = {}) => {
        const res = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                ...options.headers,
            },
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Request failed: ${res.status}`);
        }
        return res.json();
    };

    // ── WebSocket (lifecycle in messenger/useMessengerSocket.js) ──

    useMessengerSocket({
        user,
        token,
        handlers: {
            NEW_MESSAGE: (data) => handleIncomingMessage(data.message),
            NEW_GROUP_MESSAGE: (data) => handleIncomingGroupMessage(data.message),
            SECRET_SHARED: (data) => setLastEvent({ type: 'SECRET_SHARED', timestamp: Date.now(), data: data }),
            ...createGroupEventHandlers({
                user,
                fetchGroupConversations: () => fetchGroupConversations(),
                invalidateGroupSession,
                setGroupConversations,
                setActiveGroupConversation,
                activeGroupConversationRef,
            }),
        },
    });

    // ── Initial Load ───────────────────────────────────────────────

    // Load conversations once authenticated; fetchers close over the current token.
    useEffect(() => {
        if (token) {
            fetchConversations();
            fetchGroupConversations();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    // ── DM Functions ───────────────────────────────────────────────

    const handleIncomingMessage = async (msg) => {
        const senderAddr = msg.sender_address.toLowerCase();
        const myAddr = user.address.toLowerCase();
        const partnerAddr = (senderAddr === myAddr) ? msg.recipient_address.toLowerCase() : senderAddr;

        let plainText = null;
        let verified = null;
        try {
            const payload = JSON.parse(msg.content);
            if (payload.v === 1 && payload.sid) {
                const key = sessionKeysRef.current[payload.sid];
                if (key) {
                    plainText = await decryptWithSessionKey(payload.ct, key);
                }
                verified = await verifyMessageAuthenticity(msg, payload, 'dm');
            }
        } catch { /* best-effort: failure is non-fatal */ }

        const decryptedMsg = { ...msg, plainText, verified };

        // Update Active Chat if open
        const currentActive = activeConversationRef.current;
        if (currentActive && currentActive.user.address.toLowerCase() === partnerAddr) {
            setActiveConversation(prev => {
                if (!prev || prev.user.address.toLowerCase() !== partnerAddr) return prev;
                const exists = prev.messages.find(m => m.id === msg.id);
                if (exists) return prev;
                return { ...prev, messages: [...prev.messages, decryptedMsg] };
            });

            if (senderAddr !== myAddr) {
                markRead(senderAddr);
            }
        }

        // Update Conversations List
        setConversations(prev => {
            const existing = prev.find(c => c.user.address.toLowerCase() === partnerAddr);
            const otherConvos = prev.filter(c => c.user.address.toLowerCase() !== partnerAddr);

            let newConvo = existing ? { ...existing } : {
                user: { address: partnerAddr, username: "New Message" },
                last_message: msg,
                unread_count: 0
            };

            newConvo.last_message = msg;

            const isViewing = currentActive && currentActive.user.address.toLowerCase() === partnerAddr;
            if (senderAddr !== myAddr && !isViewing) {
                newConvo.unread_count = (newConvo.unread_count || 0) + 1;
            } else if (isViewing) {
                newConvo.unread_count = 0;
            }

            return [newConvo, ...otherConvos];
        });
    };

    const fetchConversations = async () => {
        try {
            const data = await api(`${API_ENDPOINTS.BASE}/messages/conversations`);
            setConversations(data);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    const loadConversation = async (partnerUser) => {
        let fullUser = partnerUser;
        if (!fullUser.encryption_public_key) {
            try {
                fullUser = await api(`${API_ENDPOINTS.BASE}/users/${partnerUser.address}`);
            } catch { /* best-effort: failure is non-fatal */ }
        }

        setActiveConversation({ user: fullUser, messages: [] });
        setMessagesLoading(true);
        markRead(partnerUser.address);

        try {
            const rawMsgs = await api(`${API_ENDPOINTS.BASE}/messages/history`, {
                method: 'POST',
                body: JSON.stringify({ partner_address: partnerUser.address })
            });
            const processed = await processMessages(rawMsgs, 'dm');
            setActiveConversation({ user: fullUser, messages: processed });
        } catch (e) { console.error(e); }
        finally { setMessagesLoading(false); }
    };

    const sendMessage = async (text, partnerUser) => {
        setSending(true);
        try {
            const recipientKey = partnerUser.encryption_public_key;
            if (!recipientKey) throw new Error("Recipient has no public key");

            const theirAddr = partnerUser.address.toLowerCase();
            let sid = activeSessionIds[theirAddr];
            let sKey = sid ? sessionKeys[sid] : null;
            let keyPayload = null;

            if (!sKey) {
                // Attestation gate (audit M-1): refuse to wrap a fresh session key
                // to a key that FAILS its identity binding (throws on 'invalid').
                await assertSafeRecipient(partnerUser);
                sid = crypto.randomUUID();
                sKey = await generateSessionKey();
                const wRecip = await wrapSessionKey(sKey, recipientKey);
                const myKey = user?.encryption_public_key || mlkemKey;
                const wSender = myKey ? await wrapSessionKey(sKey, myKey) : null;
                keyPayload = { recip: wRecip, sender: wSender };
                setSessionKeys(prev => ({ ...prev, [sid]: sKey }));
                setActiveSessionIds(prev => ({ ...prev, [theirAddr]: sid }));
            }

            const ct = await encryptWithSessionKey(text, sKey);
            // Sign the message end-to-end (audit S1): authorship is proven by the
            // sender's ML-DSA key, not asserted by the server.
            const sig = await signMessage(messageSigningBody({
                from: user.address.toLowerCase(),
                conv: theirAddr,
                sid,
                ct,
            }));
            const payload = { v: 1, sid, keys: keyPayload, ct, sig };

            const newMsg = await api(`${API_ENDPOINTS.BASE}/messages`, {
                method: 'POST',
                body: JSON.stringify({
                    recipient_address: partnerUser.address,
                    content: JSON.stringify(payload)
                })
            });

            const uiMsg = { ...newMsg, plainText: text, verified: true };
            setActiveConversation(prev => {
                if (!prev || prev.messages.some(m => m.id === newMsg.id)) return prev;
                return { ...prev, messages: [...prev.messages, uiMsg] };
            });
            setConversations(prev => {
                const partnerAddr = partnerUser.address.toLowerCase();
                const existing = prev.find(c => c.user.address.toLowerCase() === partnerAddr);
                const updated = existing
                    ? { ...existing, last_message: newMsg }
                    : { user: partnerUser, last_message: newMsg, unread_count: 0 };
                return [updated, ...prev.filter(c => c.user.address.toLowerCase() !== partnerAddr)];
            });
        } catch (e) {
            console.error(e);
            toast.error("Send failed: " + e.message);
        } finally {
            setSending(false);
        }
    };

    const markRead = async (partnerAddr) => {
        setConversations(prev => prev.map(c =>
            c.user.address.toLowerCase() === partnerAddr.toLowerCase() ? { ...c, unread_count: 0 } : c
        ));

        try {
            await fetch(`${API_ENDPOINTS.BASE}/messages/mark-read/${partnerAddr}`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
        } catch (e) { console.error("Mark read failed", e); }
    };

    // ── Group Channel Functions ─────────────────────────────────────

    const fetchGroupConversations = async () => {
        try {
            const data = await api(`${API_ENDPOINTS.GROUPS.LIST}`);
            const withNames = await resolveGroupNames(data);
            setGroupConversations(prev => {
                const unreadMap = {};
                prev.forEach(g => { unreadMap[g.channel.id] = g.unread_count || 0; });
                return withNames.map(newGroup => ({
                    ...newGroup,
                    unread_count: unreadMap[newGroup.channel.id] || 0
                }));
            });
        } catch (e) { console.error("Fetch groups failed", e); }
    };

    const createGroup = async (name, members) => {
        // members: full user objects ({address, encryption_public_key, ...}).
        // The name is E2EE for the initial member set — the server never sees it.
        const encName = await buildGroupNameBlob(name, members);
        const channel = await api(`${API_ENDPOINTS.GROUPS.CREATE}`, {
            method: 'POST',
            body: JSON.stringify({ name: encName, member_addresses: members.map(m => m.address) })
        });
        fetchGroupConversations();
        return { ...channel, display_name: name };
    };

    const addGroupMember = async (channelId, userAddress) => {
        const result = await api(`${API_ENDPOINTS.GROUPS.MEMBERS(channelId)}`, {
            method: 'POST',
            body: JSON.stringify({ user_address: userAddress })
        });
        // Add to local state synchronously (the response carries the member's
        // ML-KEM key) so the rekeyed next send wraps for them immediately, not
        // only after the WS echo. Idempotent with GROUP_MEMBER_ADDED.
        if (result?.user_address) {
            setActiveGroupConversation(prev => {
                if (!prev || prev.channel.id !== channelId) return prev;
                if (prev.channel.members.some(m => m.user_address === result.user_address)) return prev;
                return { ...prev, channel: { ...prev.channel, members: [...prev.channel.members, result] } };
            });
        }
        invalidateGroupSession(channelId);

        // Encrypted channel name (audit M-3): re-wrap it so the NEW member can
        // read it too. The adder (owner/admin) knows the plaintext and every
        // member key; removal needs no rebuild — the next rename's fresh key
        // already excludes ex-members.
        try {
            const chan = activeGroupConversationRef.current?.channel;
            if (chan && chan.id === channelId && isEncryptedTitle(chan.name)) {
                const plain = await resolveChannelName(chan);
                if (plain && plain !== LOCKED_TITLE) {
                    const memberUsers = [
                        ...chan.members.map(m => ({ address: m.user_address, ...m.user })),
                        { address: result.user_address, ...result.user },
                    ];
                    const encName = await buildGroupNameBlob(plain, memberUsers);
                    await api(`${API_ENDPOINTS.GROUPS.DETAILS(channelId)}`, {
                        method: 'PUT',
                        body: JSON.stringify({ name: encName })
                    });
                }
            }
        } catch (e) {
            // Non-fatal: the member is in and can read messages; the name shows
            // locked for them until the next rename/re-add re-wraps it.
            console.error("Re-wrapping group name for new member failed", e);
        }
        return result;
    };

    const removeGroupMember = async (channelId, userAddress) => {
        await api(`${API_ENDPOINTS.GROUPS.REMOVE_MEMBER(channelId, userAddress)}`, {
            method: 'DELETE',
        });
        // Forward secrecy (audit S2): rotate the group session key so the removed
        // member can't decrypt future messages. invalidateGroupSession forces the
        // next send to mint a fresh sid wrapped for the remaining members — but we
        // must ALSO drop the member from local state *synchronously*, before any
        // such send, or a message sent in the window before the WS echo arrives
        // would still wrap the new key for the removed member. (Idempotent with the
        // GROUP_MEMBER_REMOVED handler.)
        const removed = userAddress.toLowerCase();
        setActiveGroupConversation(prev => {
            if (!prev || prev.channel.id !== channelId) return prev;
            return {
                ...prev,
                channel: {
                    ...prev.channel,
                    members: prev.channel.members.filter(m => m.user_address !== removed),
                },
            };
        });
        invalidateGroupSession(channelId);
    };

    const updateGroupMemberRole = async (channelId, userAddress, role) => {
        return await api(`${API_ENDPOINTS.GROUPS.UPDATE_ROLE(channelId, userAddress)}`, {
            method: 'PUT',
            body: JSON.stringify({ role })
        });
    };

    const updateGroup = async (channelId, data) => {
        return await api(`${API_ENDPOINTS.GROUPS.DETAILS(channelId)}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    };

    // Rename with an E2EE name (audit M-3): fresh key wrapped for the CURRENT
    // member set only — ex-members can't read names chosen after they left.
    const renameGroup = async (channel, newName) => {
        const memberUsers = channel.members.map(m => ({ address: m.user_address, ...m.user }));
        const encName = await buildGroupNameBlob(newName, memberUsers);
        const updated = await updateGroup(channel.id, { name: encName });
        setActiveGroupConversation(prev => {
            if (!prev || prev.channel.id !== channel.id) return prev;
            return { ...prev, channel: { ...prev.channel, name: encName, display_name: newName } };
        });
        fetchGroupConversations();
        return updated;
    };

    const loadGroupConversation = async (channel) => {
        setActiveGroupConversation({ channel, messages: [] });
        setMessagesLoading(true);

        setGroupConversations(prev => prev.map(g =>
            g.channel.id === channel.id ? { ...g, unread_count: 0 } : g
        ));

        try {
            let fullChannel = channel;
            try {
                fullChannel = await api(`${API_ENDPOINTS.GROUPS.GET(channel.id)}`);
                fullChannel.display_name = await resolveChannelName(fullChannel);
            } catch { /* best-effort: failure is non-fatal */ }

            const rawMsgs = await api(`${API_ENDPOINTS.GROUPS.HISTORY(channel.id)}`, {
                method: 'POST',
                body: JSON.stringify({ limit: 50, offset: 0 })
            });
            const processed = await processMessages(rawMsgs, 'group');
            setActiveGroupConversation({ channel: fullChannel, messages: processed });
        } catch (e) { console.error(e); }
        finally { setMessagesLoading(false); }
    };

    const sendGroupMessage = async (text, channel) => {
        setSending(true);
        try {
            const members = channel.members || [];
            const channelId = channel.id;

            let sid = activeSessionIds[`group_${channelId}`];
            let sKey = sid ? sessionKeys[sid] : null;
            let keyPayload = null;

            if (!sKey) {
                sid = crypto.randomUUID();
                sKey = await generateSessionKey();

                const wrappedKeys = {};
                for (const member of members) {
                    const pubKey = member.user?.encryption_public_key;
                    if (pubKey) {
                        // Attestation gate (audit M-1): never wrap the group key to a
                        // member whose key fails its identity binding — skipping keeps
                        // the rest of the group working while that key can't read.
                        const status = await attestationStatus({ ...member.user, address: member.user_address });
                        if (status === 'invalid') {
                            console.error(`Skipping ${member.user_address}: encryption key failed attestation`);
                            toast.error(`Key verification failed for a member (${(member.user?.username) || member.user_address.slice(0, 12) + '…'}) — they were excluded from this message.`);
                            continue;
                        }
                        wrappedKeys[member.user_address] = await wrapSessionKey(sKey, pubKey);
                    }
                }

                keyPayload = wrappedKeys;
                setSessionKeys(prev => ({ ...prev, [sid]: sKey }));
                setActiveSessionIds(prev => ({ ...prev, [`group_${channelId}`]: sid }));
            }

            const ct = await encryptWithSessionKey(text, sKey);
            // Sign end-to-end (audit S1) — critical for groups, where every member
            // holds the session key and could otherwise forge as another member.
            const sig = await signMessage(messageSigningBody({
                from: user.address.toLowerCase(),
                conv: channelId,
                sid,
                ct,
            }));
            const payload = { v: 2, sid, gid: channelId, keys: keyPayload, ct, sig };

            const newMsg = await api(`${API_ENDPOINTS.GROUPS.MESSAGES(channelId)}`, {
                method: 'POST',
                body: JSON.stringify({ content: JSON.stringify(payload) })
            });

            const uiMsg = { ...newMsg, plainText: text, verified: true };
            setActiveGroupConversation(prev => {
                if (!prev || prev.messages.some(m => m.id === newMsg.id)) return prev;
                return { ...prev, messages: [...prev.messages, uiMsg] };
            });
            fetchGroupConversations();
        } catch (e) {
            console.error(e);
            toast.error("Send failed: " + e.message);
        } finally {
            setSending(false);
        }
    };

    const handleIncomingGroupMessage = async (msg) => {
        const senderAddr = msg.sender_address.toLowerCase();
        const myAddr = user.address.toLowerCase();
        const channelId = msg.channel_id;

        let plainText = null;
        let verified = null;
        try {
            const payload = JSON.parse(msg.content);
            if (payload.v === 2 && payload.sid) {
                const key = sessionKeysRef.current[payload.sid];
                if (key) {
                    plainText = await decryptWithSessionKey(payload.ct, key);
                }
                verified = await verifyMessageAuthenticity(msg, payload, 'group');
            }
        } catch { /* best-effort: failure is non-fatal */ }

        const decryptedMsg = { ...msg, plainText, verified };

        // Update active group chat if open
        const currentActive = activeGroupConversationRef.current;
        if (currentActive && currentActive.channel.id === channelId) {
            setActiveGroupConversation(prev => {
                if (!prev || prev.channel.id !== channelId) return prev;
                const exists = prev.messages.find(m => m.id === msg.id);
                if (exists) return prev;
                return { ...prev, messages: [...prev.messages, decryptedMsg] };
            });
        }

        // Update group conversations list
        setGroupConversations(prev => {
            const existing = prev.find(g => g.channel.id === channelId);
            if (!existing) {
                fetchGroupConversations();
                return prev;
            }

            const isViewing = currentActive && currentActive.channel.id === channelId;

            return prev.map(g => {
                if (g.channel.id !== channelId) return g;

                let newUnread = g.unread_count || 0;
                if (!isViewing && senderAddr !== myAddr) {
                    newUnread += 1;
                } else if (isViewing) {
                    newUnread = 0;
                }

                return { ...g, last_message: msg, unread_count: newUnread };
            });
        });
    };

    // ── Computed Values ────────────────────────────────────────────

    const unreadCount = useMemo(() =>
        conversations.reduce((acc, c) => acc + (c.unread_count || 0), 0) +
        groupConversations.reduce((acc, g) => acc + (g.unread_count || 0), 0),
        [conversations, groupConversations]
    );

    return (
        <MessengerContext.Provider value={{
            conversations,
            activeConversation,
            loading,
            messagesLoading,
            sending,
            loadConversation,
            sendMessage,
            setActiveConversation,
            handleManualDecrypt: (msg) => handleManualDecrypt(msg, 'dm'),
            unreadCount,
            lastEvent,
            // Group Channels
            groupConversations,
            activeGroupConversation,
            setActiveGroupConversation,
            createGroup,
            loadGroupConversation,
            sendGroupMessage,
            fetchGroupConversations,
            handleGroupManualDecrypt: (msg) => handleManualDecrypt(msg, 'group'),
            addGroupMember,
            removeGroupMember,
            updateGroupMemberRole,
            updateGroup,
            renameGroup,
        }}>
            {children}
        </MessengerContext.Provider>
    );
};
