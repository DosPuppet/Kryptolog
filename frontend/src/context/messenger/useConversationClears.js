import { useCallback, useState } from 'react';
import { API_ENDPOINTS } from '../../config';
import { fetchAllPages, pageUrl } from '../../utils/paging';

// "Delete this conversation" as a VIEW: hide it up to a message id (audit
// 2026-09-11 M-6). The marker is stored server-side so every device agrees, and
// computed there too — this hook only applies it.
//
// Applied to what is SHOWN, never to what is processed: a hidden message may
// still be the one carrying the key for a newer, visible message of the same
// session, so the pipelines in useMessageSessions see every row and only the
// lists handed to the UI are filtered.
//
// A conversation comes back by itself when something newer than the marker
// arrives — the same "clear chat" every messenger has.
const keyOf = (kind, conversation) => `${kind}:${String(conversation).toLowerCase()}`;

export const useConversationClears = (api) => {
    const [clears, setClears] = useState({});

    const fetchClears = useCallback(async () => {
        try {
            const rows = await fetchAllPages(
                (page) => api(pageUrl(API_ENDPOINTS.CONVERSATIONS.CLEARS, page))
            );
            setClears(Object.fromEntries(
                rows.map((r) => [keyOf(r.kind, r.conversation), r.cleared_through_id])
            ));
        } catch (e) { console.error('Fetch conversation clears failed', e); }
    }, [api]);

    /** Ask the server to hide a conversation for this user; record its marker. */
    const clearConversation = useCallback(async (kind, conversation) => {
        const row = await api(API_ENDPOINTS.CONVERSATIONS.CLEAR(kind, conversation), { method: 'POST' });
        setClears((prev) => ({ ...prev, [keyOf(row.kind, row.conversation)]: row.cleared_through_id }));
        return row;
    }, [api]);

    /** Is a conversation whose newest message is `lastId` hidden for this user? */
    const isHidden = useCallback((kind, conversation, lastId) => {
        const marker = clears[keyOf(kind, conversation)];
        if (marker == null) return false;
        return lastId == null || lastId <= marker;
    }, [clears]);

    /** The messages of a conversation that are still shown. */
    const visible = useCallback((kind, conversation, messages) => {
        const marker = clears[keyOf(kind, conversation)];
        if (marker == null || !Array.isArray(messages)) return messages;
        return messages.filter((m) => m.id == null || m.id > marker);
    }, [clears]);

    return { fetchClears, clearConversation, isHidden, visible };
};
