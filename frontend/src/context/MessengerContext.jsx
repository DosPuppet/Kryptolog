import { createContext, useContext, useState, useEffect, useRef, useMemo } from 'react';
import { useAuth } from './AuthContext';
import { usePQC } from './PQCContext';
import API_ENDPOINTS from '../config';
import { encryptWithSessionKey, decryptWithSessionKey } from '../utils/crypto';

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
    const { generateSessionKey, wrapSessionKey, unwrapSessionKey, unwrapManySessionKeys, kyberKey } = usePQC();

    const [conversations, setConversations] = useState([]);
    const [activeConversation, setActiveConversation] = useState(null); // { user, messages: [] }
    const activeConversationRef = useRef(null);
    useEffect(() => { activeConversationRef.current = activeConversation; }, [activeConversation]);

    const [sessionKeys, setSessionKeys] = useState({});
    const sessionKeysRef = useRef({});
    useEffect(() => { sessionKeysRef.current = sessionKeys; }, [sessionKeys]);

    const [activeSessionIds, setActiveSessionIds] = useState({});
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

    // WebSocket Ref to prevent re-renders
    const wsRef = useRef(null);

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

    /** Force session key rotation for a group (used on member add/remove). */
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
     * @param {Object} [partnerUser] - Partner user (DMs only)
     */
    const processMessages = async (rawMsgs, mode = 'dm', partnerUser = null) => {
        const myAddr = user.address.toLowerCase();
        const version = mode === 'dm' ? 1 : 2;

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

                return await Promise.all(processed.map(async m => {
                    if (m._sessionPayload && newKeys[m._sessionPayload.sid]) {
                        try {
                            const pt = await decryptWithSessionKey(m._sessionPayload.ct, newKeys[m._sessionPayload.sid]);
                            return { ...m, plainText: pt };
                        } catch { /* best-effort: failure is non-fatal */ }
                    }
                    return m;
                }));
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

        return processed;
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

    // ── WebSocket Setup ────────────────────────────────────────────

    useEffect(() => {
        if (!user || user.authType === 'metamask') return;

        let ws = null;
        let heartbeatInterval = null;
        let reconnectTimeout = null;
        let retryCount = 0;
        const maxRetries = 10;
        let isUnmounting = false;

        // Visibility / focus handlers — added ONCE, cleaned up on unmount
        const sendFocusState = () => {
            const currentWs = wsRef.current;
            if (currentWs && currentWs.readyState === WebSocket.OPEN) {
                const focused = document.visibilityState === 'visible';
                currentWs.send(JSON.stringify({ type: focused ? 'APP_FOCUSED' : 'APP_BLURRED' }));
            }
        };
        const onFocus = () => {
            const currentWs = wsRef.current;
            if (currentWs && currentWs.readyState === WebSocket.OPEN) {
                currentWs.send(JSON.stringify({ type: 'APP_FOCUSED' }));
            }
        };
        const onBlur = () => {
            const currentWs = wsRef.current;
            if (currentWs && currentWs.readyState === WebSocket.OPEN) {
                currentWs.send(JSON.stringify({ type: 'APP_BLURRED' }));
            }
        };

        document.addEventListener('visibilitychange', sendFocusState);
        window.addEventListener('focus', onFocus);
        window.addEventListener('blur', onBlur);

        const connect = () => {
            if (isUnmounting) return;

            const url = API_ENDPOINTS.BASE.replace('http', 'ws');
            const wsUrl = `${url}/ws`;
            ws = new WebSocket(wsUrl);
            wsRef.current = ws;

            ws.onopen = () => {
                retryCount = 0;
                ws.send(JSON.stringify({ type: 'AUTH', token }));

                if (document.visibilityState === 'visible') {
                    ws.send(JSON.stringify({ type: 'APP_FOCUSED' }));
                }

                // Start Heartbeat
                if (heartbeatInterval) clearInterval(heartbeatInterval);
                heartbeatInterval = setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        console.debug("WS Sending PING");
                        ws.send(JSON.stringify({ type: 'PING' }));
                    }
                }, 30000);
            };

            ws.onmessage = async (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'NEW_MESSAGE') {
                        await handleIncomingMessage(data.message);
                    } else if (data.type === 'NEW_GROUP_MESSAGE') {
                        await handleIncomingGroupMessage(data.message);
                    } else if (data.type === 'GROUP_CREATED') {
                        fetchGroupConversations();
                    } else if (data.type === 'GROUP_MEMBER_ADDED') {
                        fetchGroupConversations();
                        invalidateGroupSession(data.channel_id);

                        const currentActive = activeGroupConversationRef.current;
                        if (currentActive && currentActive.channel.id === data.channel_id) {
                            if (data.new_member) {
                                setActiveGroupConversation(prev => {
                                    if (!prev || prev.channel.id !== data.channel_id) return prev;
                                    if (prev.channel.members.some(m => m.user_address === data.new_member.user_address)) return prev;
                                    const newMember = {
                                        ...data.new_member,
                                        user: {
                                            address: data.new_member.user_address,
                                            username: data.new_member.username,
                                            encryption_public_key: data.new_member.encryption_public_key
                                        }
                                    };
                                    return {
                                        ...prev,
                                        channel: { ...prev.channel, members: [...prev.channel.members, newMember] }
                                    };
                                });
                            }
                        }
                    } else if (data.type === 'GROUP_MEMBER_UPDATED') {
                        fetchGroupConversations();
                        const currentActive = activeGroupConversationRef.current;
                        if (currentActive && currentActive.channel.id === data.channel_id) {
                            setActiveGroupConversation(prev => {
                                if (!prev || prev.channel.id !== data.channel_id) return prev;
                                return {
                                    ...prev,
                                    channel: {
                                        ...prev.channel,
                                        members: prev.channel.members.map(m =>
                                            m.user_address === data.member.user_address
                                                ? { ...m, role: data.member.role }
                                                : m
                                        ),
                                        owner_address: data.member.role === 'owner' ? data.member.user_address : prev.channel.owner_address
                                    }
                                };
                            });
                        }
                    } else if (data.type === 'GROUP_UPDATED') {
                        fetchGroupConversations();
                        const currentActive = activeGroupConversationRef.current;
                        if (currentActive && currentActive.channel.id === data.channel_id) {
                            setActiveGroupConversation(prev => ({
                                ...prev,
                                channel: { ...prev.channel, name: data.name }
                            }));
                        }
                    } else if (data.type === 'GROUP_MEMBER_REMOVED') {
                        if (data.removed_address === user.address.toLowerCase()) {
                            setGroupConversations(prev => prev.filter(g => g.channel.id !== data.channel_id));
                            const currentActive = activeGroupConversationRef.current;
                            if (currentActive && currentActive.channel.id === data.channel_id) {
                                setActiveGroupConversation(null);
                            }
                        } else {
                            fetchGroupConversations();
                            invalidateGroupSession(data.channel_id);

                            const currentActive = activeGroupConversationRef.current;
                            if (currentActive && currentActive.channel.id === data.channel_id) {
                                setActiveGroupConversation(prev => ({
                                    ...prev,
                                    channel: {
                                        ...prev.channel,
                                        members: prev.channel.members.filter(m => m.user_address !== data.removed_address)
                                    }
                                }));
                            }
                        }
                    } else if (data.type === 'SECRET_SHARED') {
                        setLastEvent({ type: 'SECRET_SHARED', timestamp: Date.now(), data: data });
                    }
                } catch (e) {
                    console.error("WS Parse Error", e);
                }
            };

            ws.onclose = (e) => {
                if (heartbeatInterval) clearInterval(heartbeatInterval);

                if (!isUnmounting && retryCount < maxRetries) {
                    const timeout = Math.min(1000 * (2 ** retryCount), 30000);
                    reconnectTimeout = setTimeout(() => {
                        retryCount++;
                        connect();
                    }, timeout);
                }
            };

            ws.onerror = (err) => {
                console.error("WS Error:", err);
                ws.close();
            };
        };

        connect();

        return () => {
            isUnmounting = true;
            document.removeEventListener('visibilitychange', sendFocusState);
            window.removeEventListener('focus', onFocus);
            window.removeEventListener('blur', onBlur);
            if (heartbeatInterval) clearInterval(heartbeatInterval);
            if (reconnectTimeout) clearTimeout(reconnectTimeout);
            if (wsRef.current) {
                wsRef.current.close();
                wsRef.current = null;
            }
        };
        // Reconnect only on identity/token change. The handlers called inside
        // ws.onmessage are intentionally excluded — including them would tear
        // down and rebuild the socket on every render.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user?.address, token]);

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
        try {
            const payload = JSON.parse(msg.content);
            if (payload.v === 1 && payload.sid) {
                const key = sessionKeysRef.current[payload.sid];
                if (key) {
                    plainText = await decryptWithSessionKey(payload.ct, key);
                }
            }
        } catch { /* best-effort: failure is non-fatal */ }

        const decryptedMsg = { ...msg, plainText };

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
            const processed = await processMessages(rawMsgs, 'dm', fullUser);
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
                sid = crypto.randomUUID();
                sKey = await generateSessionKey();
                const wRecip = await wrapSessionKey(sKey, recipientKey);
                const myKey = user?.encryption_public_key || kyberKey;
                const wSender = myKey ? await wrapSessionKey(sKey, myKey) : null;
                keyPayload = { recip: wRecip, sender: wSender };
                setSessionKeys(prev => ({ ...prev, [sid]: sKey }));
                setActiveSessionIds(prev => ({ ...prev, [theirAddr]: sid }));
            }

            const ct = await encryptWithSessionKey(text, sKey);
            const payload = { v: 1, sid, keys: keyPayload, ct };

            const newMsg = await api(`${API_ENDPOINTS.BASE}/messages`, {
                method: 'POST',
                body: JSON.stringify({
                    recipient_address: partnerUser.address,
                    content: JSON.stringify(payload)
                })
            });

            const uiMsg = { ...newMsg, plainText: text };
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
            alert("Send failed: " + e.message);
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
            setGroupConversations(prev => {
                const unreadMap = {};
                prev.forEach(g => { unreadMap[g.channel.id] = g.unread_count || 0; });
                return data.map(newGroup => ({
                    ...newGroup,
                    unread_count: unreadMap[newGroup.channel.id] || 0
                }));
            });
        } catch (e) { console.error("Fetch groups failed", e); }
    };

    const createGroup = async (name, memberAddresses) => {
        const channel = await api(`${API_ENDPOINTS.GROUPS.CREATE}`, {
            method: 'POST',
            body: JSON.stringify({ name, member_addresses: memberAddresses })
        });
        fetchGroupConversations();
        return channel;
    };

    const addGroupMember = async (channelId, userAddress) => {
        const result = await api(`${API_ENDPOINTS.GROUPS.MEMBERS(channelId)}`, {
            method: 'POST',
            body: JSON.stringify({ user_address: userAddress })
        });
        invalidateGroupSession(channelId);
        return result;
    };

    const removeGroupMember = async (channelId, userAddress) => {
        await api(`${API_ENDPOINTS.GROUPS.REMOVE_MEMBER(channelId, userAddress)}`, {
            method: 'DELETE',
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
                        wrappedKeys[member.user_address] = await wrapSessionKey(sKey, pubKey);
                    }
                }

                keyPayload = wrappedKeys;
                setSessionKeys(prev => ({ ...prev, [sid]: sKey }));
                setActiveSessionIds(prev => ({ ...prev, [`group_${channelId}`]: sid }));
            }

            const ct = await encryptWithSessionKey(text, sKey);
            const payload = { v: 2, sid, gid: channelId, keys: keyPayload, ct };

            const newMsg = await api(`${API_ENDPOINTS.GROUPS.MESSAGES(channelId)}`, {
                method: 'POST',
                body: JSON.stringify({ content: JSON.stringify(payload) })
            });

            const uiMsg = { ...newMsg, plainText: text };
            setActiveGroupConversation(prev => {
                if (!prev || prev.messages.some(m => m.id === newMsg.id)) return prev;
                return { ...prev, messages: [...prev.messages, uiMsg] };
            });
            fetchGroupConversations();
        } catch (e) {
            console.error(e);
            alert("Send failed: " + e.message);
        } finally {
            setSending(false);
        }
    };

    const handleIncomingGroupMessage = async (msg) => {
        const senderAddr = msg.sender_address.toLowerCase();
        const myAddr = user.address.toLowerCase();
        const channelId = msg.channel_id;

        let plainText = null;
        try {
            const payload = JSON.parse(msg.content);
            if (payload.v === 2 && payload.sid) {
                const key = sessionKeysRef.current[payload.sid];
                if (key) {
                    plainText = await decryptWithSessionKey(payload.ct, key);
                }
            }
        } catch { /* best-effort: failure is non-fatal */ }

        const decryptedMsg = { ...msg, plainText };

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
        }}>
            {children}
        </MessengerContext.Provider>
    );
};
