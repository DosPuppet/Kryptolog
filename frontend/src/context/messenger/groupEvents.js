// Group-membership WebSocket events → local state updates. Factory returning a
// { EVENT_TYPE: handler } map for useMessengerSocket; the context supplies its
// state setters. Membership changes also drop the active group session key
// (audit S2) so the next send rekeys for the current member set — see the
// rotation notes in useMessageSessions.
export const createGroupEventHandlers = ({
    user,
    fetchGroupConversations,
    invalidateGroupSession,
    setGroupConversations,
    setActiveGroupConversation,
    activeGroupConversationRef,
}) => ({
    GROUP_CREATED: () => {
        fetchGroupConversations();
    },

    GROUP_MEMBER_ADDED: (data) => {
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
    },

    GROUP_MEMBER_UPDATED: (data) => {
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
    },

    GROUP_UPDATED: (data) => {
        fetchGroupConversations();
        const currentActive = activeGroupConversationRef.current;
        if (currentActive && currentActive.channel.id === data.channel_id) {
            setActiveGroupConversation(prev => ({
                ...prev,
                channel: { ...prev.channel, name: data.name }
            }));
        }
    },

    GROUP_MEMBER_REMOVED: (data) => {
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
    },
});
