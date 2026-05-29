import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useMessenger } from '../hooks/useMessenger';
import { Loader2 } from 'lucide-react';

// Components
import ConversationList from './messenger/ConversationList';
import ChatArea from './messenger/ChatArea';
import GroupChatArea from './messenger/GroupChatArea';
import NewChatModal from './messenger/NewChatModal';
import CreateGroupModal from './messenger/CreateGroupModal';

export default function Messenger() {
    const {
        conversations,
        activeConversation,
        loading,
        messagesLoading,
        sending,
        loadConversation,
        sendMessage,
        setActiveConversation,
        handleManualDecrypt,
        // Group Channels
        groupConversations,
        activeGroupConversation,
        setActiveGroupConversation,
        createGroup,
        loadGroupConversation,
        sendGroupMessage,
        handleGroupManualDecrypt,
    } = useMessenger();

    const [isNewChatOpen, setIsNewChatOpen] = useState(false);
    const [isNewGroupOpen, setIsNewGroupOpen] = useState(false);

    // Cleanup when leaving messenger view
    React.useEffect(() => {
        return () => {
            setActiveConversation(null);
            setActiveGroupConversation(null);
        };
    }, [setActiveConversation, setActiveGroupConversation]);

    const handleStartNewChat = (partnerUser) => {
        setActiveGroupConversation(null);
        loadConversation(partnerUser);
        setIsNewChatOpen(false);
    };

    const handleSelectGroup = (channel) => {
        setActiveConversation(null);
        loadGroupConversation(channel);
    };

    const handleSelectDM = (user) => {
        setActiveGroupConversation(null);
        loadConversation(user);
    };

    const handleCreateGroup = async (name, memberAddresses) => {
        const channel = await createGroup(name, memberAddresses);
        if (channel) {
            setActiveConversation(null);
            loadGroupConversation(channel);
        }
    };

    const handleBackFromChat = () => {
        setActiveConversation(null);
        setActiveGroupConversation(null);
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-full">
                <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
            </div>
        );
    }

    return (
        <div className="flex h-full bg-slate-50 dark:bg-slate-850 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700">
            <ConversationList
                conversations={conversations}
                activeConversation={activeConversation}
                onSelect={handleSelectDM}
                onNewChat={() => setIsNewChatOpen(true)}
                groupConversations={groupConversations}
                activeGroupConversation={activeGroupConversation}
                onSelectGroup={handleSelectGroup}
                onNewGroup={() => setIsNewGroupOpen(true)}
            />

            {activeGroupConversation ? (
                <GroupChatArea
                    activeGroupConversation={activeGroupConversation}
                    onBack={handleBackFromChat}
                    onSend={sendGroupMessage}
                    loadingMessages={messagesLoading}
                    sending={sending}
                    onDecrypt={handleGroupManualDecrypt}
                />
            ) : (
                <ChatArea
                    activeConversation={activeConversation}
                    onBack={handleBackFromChat}
                    onSend={sendMessage}
                    loadingMessages={messagesLoading}
                    sending={sending}
                    onDecrypt={handleManualDecrypt}
                />
            )}

            <NewChatModal
                isOpen={isNewChatOpen}
                onClose={() => setIsNewChatOpen(false)}
                onStartChat={handleStartNewChat}
            />

            <CreateGroupModal
                isOpen={isNewGroupOpen}
                onClose={() => setIsNewGroupOpen(false)}
                onCreate={handleCreateGroup}
            />
        </div>
    );
}
