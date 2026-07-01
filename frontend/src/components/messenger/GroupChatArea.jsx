import { useState, useEffect, useRef } from 'react';
import { ArrowLeft, Shield, Loader2, Send, Lock, Users, UserPlus, UserMinus, Crown, ShieldCheck, Edit2, Check, X } from 'lucide-react';
import MessageAuthBadge from './MessageAuthBadge';
import { useAuth } from '../../context/AuthContext';
import { useMessengerContext } from '../../context/MessengerContext';
import AddMemberModal from './AddMemberModal';
import { toast } from '../../utils/toast';
import { confirmDialog } from '../../utils/confirm';

const GroupChatArea = ({ activeGroupConversation, onBack, onSend, loadingMessages, sending, onDecrypt }) => {
    const { user } = useAuth();
    const { addGroupMember, removeGroupMember, updateGroupMemberRole, updateGroup } = useMessengerContext();
    const [inputText, setInputText] = useState('');
    const [showMembers, setShowMembers] = useState(false);
    const [isAddMemberModalOpen, setIsAddMemberModalOpen] = useState(false);
    const [isEditingName, setIsEditingName] = useState(false);
    const [editNameValue, setEditNameValue] = useState('');
    const [trackedChannel, setTrackedChannel] = useState(null);
    const messagesEndRef = useRef(null);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [activeGroupConversation?.messages]);

    // Seed the editable name whenever the active channel changes. Render-time
    // reset instead of a setState-in-effect.
    const activeChannel = activeGroupConversation?.channel;
    if (activeChannel && activeChannel !== trackedChannel) {
        setTrackedChannel(activeChannel);
        setEditNameValue(activeChannel.name);
    }

    const handleSend = (e) => {
        e.preventDefault();
        if (!inputText.trim()) return;
        onSend(inputText, activeGroupConversation.channel);
        setInputText('');
    };

    if (!activeGroupConversation) {
        return (
            <div className="hidden md:flex flex-1 flex-col items-center justify-center text-slate-400 p-8 bg-slate-50 dark:bg-slate-900">
                <div className="w-20 h-20 bg-slate-100 dark:bg-slate-750 rounded-full flex items-center justify-center mb-4">
                    <Users className="w-10 h-10 text-slate-300 dark:text-slate-600" />
                </div>
                <p>Select a group to start chatting</p>
            </div>
        );
    }

    const channel = activeGroupConversation.channel;
    const members = channel.members || [];

    const myMember = members.find(m => m.user_address === user.address);
    const isOwner = myMember?.role === 'owner';
    const isAdmin = myMember?.role === 'admin';
    const canManageMembers = isOwner || isAdmin;

    const handleAddMember = async (address) => {
        await addGroupMember(channel.id, address);
    };

    const handleRemoveMember = async (targetMember) => {
        const isTargetOwner = targetMember.role === 'owner';
        const ok = await confirmDialog(
            isTargetOwner
                ? {
                    title: 'Remove the Group Owner?',
                    message: 'You are removing the Group Owner. YOU will become the new Owner. Continue?',
                    confirmText: 'Remove & take ownership',
                    danger: true,
                }
                : {
                    title: 'Remove this member?',
                    confirmText: 'Remove',
                    danger: true,
                }
        );
        if (ok) {
            await removeGroupMember(channel.id, targetMember.user_address);
        }
    };

    const handlePromote = async (member) => {
        if (await confirmDialog({ title: `Promote ${member.user?.username || 'member'} to Admin?`, confirmText: 'Promote' })) {
            await updateGroupMemberRole(channel.id, member.user_address, 'admin');
        }
    };

    const handleDemote = async (member) => {
        if (await confirmDialog({ title: `Demote ${member.user?.username || 'member'} to Member?`, confirmText: 'Demote' })) {
            await updateGroupMemberRole(channel.id, member.user_address, 'member');
        }
    };

    const handleRename = async () => {
        if (!editNameValue.trim() || editNameValue === channel.name) {
            setIsEditingName(false);
            return;
        }
        try {
            await updateGroup(channel.id, { name: editNameValue });
            setIsEditingName(false);
        } catch (e) {
            toast.error("Failed to rename group");
        }
    };

    const roleIcon = (role) => {
        if (role === 'owner') return <Crown className="w-3.5 h-3.5 text-amber-500" />;
        if (role === 'admin') return <ShieldCheck className="w-3.5 h-3.5 text-blue-500" />;
        return null;
    };

    const getSenderName = (senderAddr) => {
        const member = members.find(m => m.user_address === senderAddr);
        if (member?.user?.username) return member.user.username;
        return `${senderAddr.substring(0, 8)}...`;
    };

    const getSenderInitial = (senderAddr) => {
        const name = getSenderName(senderAddr);
        return name.substring(0, 1).toUpperCase();
    };

    // Simple hash for consistent avatar colors
    const getAvatarColor = (addr) => {
        const colors = [
            'from-indigo-500 to-purple-500',
            'from-emerald-500 to-teal-500',
            'from-rose-500 to-pink-500',
            'from-amber-500 to-orange-500',
            'from-cyan-500 to-blue-500',
            'from-violet-500 to-fuchsia-500',
        ];
        let hash = 0;
        for (let i = 0; i < addr.length; i++) hash = addr.charCodeAt(i) + ((hash << 5) - hash);
        return colors[Math.abs(hash) % colors.length];
    };

    return (
        <div className="flex flex-1 flex-col bg-slate-50 dark:bg-slate-900 h-full">
            {/* Header */}
            <div className="p-4 bg-white dark:bg-slate-850 border-b border-slate-200 dark:border-slate-700 flex items-center gap-3 shadow-sm z-10">
                <button onClick={onBack} className="md:hidden p-2 -ml-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-full">
                    <ArrowLeft className="w-5 h-5 dark:text-white" />
                </button>
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center text-white font-bold shadow-sm">
                    <Users className="w-4 h-4" />
                </div>
                <div className="flex-1 overflow-hidden">
                    {isEditingName ? (
                        <div className="flex items-center gap-2">
                            <input
                                type="text"
                                value={editNameValue}
                                onChange={e => setEditNameValue(e.target.value)}
                                className="bg-slate-100 dark:bg-slate-750 border border-slate-300 dark:border-slate-600 rounded px-2 py-1 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-indigo-500 w-full"
                                autoFocus
                                onKeyDown={e => { if (e.key === 'Enter') handleRename(); if (e.key === 'Escape') setIsEditingName(false); }}
                            />
                            <button onClick={handleRename} className="p-1 text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20 rounded"><Check className="w-4 h-4" /></button>
                            <button onClick={() => setIsEditingName(false)} className="p-1 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"><X className="w-4 h-4" /></button>
                        </div>
                    ) : (
                        <div className="group flex items-center gap-2">
                            <h3 className="font-bold text-slate-900 dark:text-white truncate">{channel.name}</h3>
                            {isOwner && (
                                <button onClick={() => setIsEditingName(true)} className="opacity-0 group-hover:opacity-100 p-1 text-slate-400 hover:text-indigo-500 transition-all">
                                    <Edit2 className="w-3 h-3" />
                                </button>
                            )}
                        </div>
                    )}
                    <div className="flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                        <Shield className="w-3 h-3" /> E2E Encrypted · {members.length} members
                    </div>
                </div>
                <button
                    onClick={() => setShowMembers(!showMembers)}
                    className={`p-2 rounded-lg transition-colors ${showMembers ? 'bg-indigo-100 dark:bg-indigo-900/40 text-indigo-600 dark:text-indigo-400' : 'hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400'}`}
                >
                    <Users className="w-5 h-5" />
                </button>
            </div>

            <div className="flex flex-1 overflow-hidden">
                {/* Messages */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                    {loadingMessages ? (
                        <div className="flex justify-center p-8">
                            <Loader2 className="w-8 h-8 animate-spin text-slate-400" />
                        </div>
                    ) : (
                        (() => {
                        // F-2: a member who has signed before sending an unsigned
                        // message is suspicious (likely signature-stripping).
                        const hasPeerSignedHistory = activeGroupConversation.messages.some(
                            m => m.verified === true && m.sender_address !== user.address
                        );
                        return activeGroupConversation.messages.map(msg => {
                            const isMe = msg.sender_address === user.address;
                            return (
                                <div key={msg.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
                                    {!isMe && (
                                        <div className={`w-7 h-7 rounded-full bg-gradient-to-br ${getAvatarColor(msg.sender_address)} flex items-center justify-center text-white text-xs font-bold mr-2 mt-auto mb-1 shrink-0`}>
                                            {getSenderInitial(msg.sender_address)}
                                        </div>
                                    )}
                                    <div className={`max-w-[75%] rounded-2xl px-4 py-3 shadow-sm transition-all ${isMe
                                        ? 'bg-indigo-600 text-white rounded-br-none'
                                        : 'bg-white dark:bg-slate-750 text-slate-800 dark:text-white rounded-bl-none border border-slate-200 dark:border-slate-600'}`}
                                    >
                                        {!isMe && (
                                            <div className="text-xs font-semibold text-indigo-500 dark:text-indigo-400 mb-1">
                                                {getSenderName(msg.sender_address)}
                                            </div>
                                        )}
                                        {msg.plainText ? (
                                            <p className="text-sm">{msg.plainText}</p>
                                        ) : (
                                            <button onClick={() => onDecrypt(msg)}
                                                className={`flex items-center gap-2 text-sm font-semibold px-2 py-1 rounded bg-black/10 hover:bg-black/20 dark:bg-white/10 dark:hover:bg-white/20 transition-colors ${isMe ? 'text-white' : 'text-indigo-500 dark:text-indigo-400'}`}
                                            >
                                                <Lock className="w-4 h-4" /> Click to Decrypt
                                            </button>
                                        )}
                                        <div className={`flex items-center gap-1 text-[10px] mt-1 opacity-70 ${isMe ? 'text-indigo-100' : 'text-slate-400'}`}>
                                            {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                            {/* Authenticity (audit S1/F-2): in groups every member holds the
                                                session key, so a per-message signature is what proves the author. */}
                                            {!isMe && (
                                                <MessageAuthBadge verified={msg.verified} suspicious={hasPeerSignedHistory} />
                                            )}
                                        </div>
                                    </div>
                                </div>
                            );
                        });
                        })()
                    )}
                    <div ref={messagesEndRef} />
                </div>

                {/* Members Panel */}
                {showMembers && (
                    <div className="w-64 border-l border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-850 overflow-y-auto flex flex-col">
                        <div className="p-3 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center bg-slate-50 dark:bg-slate-900/50">
                            <h4 className="font-semibold text-sm text-slate-900 dark:text-white">Members ({members.length})</h4>
                            {canManageMembers && (
                                <button
                                    onClick={() => setIsAddMemberModalOpen(true)}
                                    className="p-1.5 bg-indigo-100 dark:bg-indigo-900/40 text-indigo-600 dark:text-indigo-400 rounded-lg hover:bg-indigo-200 dark:hover:bg-indigo-900/60 transition-colors"
                                    title="Add Member"
                                >
                                    <UserPlus className="w-4 h-4" />
                                </button>
                            )}
                        </div>
                        <div className="p-2 space-y-1 flex-1">
                            {members.map(m => (
                                <div key={m.user_address} className="flex items-center gap-2 p-2 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors group">
                                    <div className={`w-8 h-8 rounded-full bg-gradient-to-br ${getAvatarColor(m.user_address)} flex items-center justify-center text-white text-xs font-bold shrink-0`}>
                                        {(m.user?.username || m.user_address).substring(0, 1).toUpperCase()}
                                    </div>
                                    <div className="flex-1 overflow-hidden">
                                        <div className="flex items-center gap-1">
                                            <span className="text-sm font-medium text-slate-900 dark:text-white truncate">
                                                {m.user?.username || `${m.user_address.substring(0, 8)}...`}
                                            </span>
                                            {roleIcon(m.role)}
                                        </div>
                                        <div className="text-[10px] text-slate-400 font-mono truncate">{m.user_address.substring(0, 12)}...</div>
                                    </div>

                                    {/* Action Buttons */}
                                    <div className="opacity-0 group-hover:opacity-100 flex items-center gap-1">
                                        {/* Promote/Demote - Only Owner can do this */}
                                        {isOwner && m.user_address !== user.address && (
                                            <>
                                                {m.role === 'member' && (
                                                    <button onClick={() => handlePromote(m)} className="p-1.5 text-slate-400 hover:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded" title="Promote to Admin">
                                                        <ShieldCheck className="w-4 h-4" />
                                                    </button>
                                                )}
                                                {m.role === 'admin' && (
                                                    <button onClick={() => handleDemote(m)} className="p-1.5 text-slate-400 hover:text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded" title="Demote to Member">
                                                        <Users className="w-4 h-4" />
                                                    </button>
                                                )}
                                            </>
                                        )}

                                        {/* Remove - Owner can remove anyone; Admin can remove Member or Owner (taking ownership) */}
                                        {m.user_address !== user.address && (
                                            (isOwner) ||
                                            (isAdmin && (m.role === 'member' || m.role === 'owner'))
                                        ) && (
                                                <button
                                                    onClick={() => handleRemoveMember(m)}
                                                    className="p-1.5 text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                                                    title={m.role === 'owner' ? "Remove Owner & Take Ownership" : "Remove Member"}
                                                >
                                                    <UserMinus className="w-4 h-4" />
                                                </button>
                                            )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            {/* Input */}
            <div className="p-4 bg-white dark:bg-slate-850 border-t border-slate-200 dark:border-slate-700">
                <form onSubmit={handleSend} className="flex gap-2">
                    <input
                        type="text"
                        value={inputText}
                        onChange={(e) => setInputText(e.target.value)}
                        placeholder="Type a secure message..."
                        className="flex-1 bg-slate-100 dark:bg-slate-750 border-0 rounded-xl px-4 py-3 focus:ring-2 focus:ring-indigo-500 dark:text-white outline-none transition-all"
                    />
                    <button
                        type="submit"
                        disabled={!inputText.trim() || sending}
                        className="bg-indigo-600 hover:bg-indigo-500 text-white p-3 rounded-xl transition-all disabled:opacity-50 disabled:scale-95 shadow-lg shadow-indigo-500/20"
                    >
                        {sending ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
                    </button>
                </form>
            </div>

            <AddMemberModal
                isOpen={isAddMemberModalOpen}
                onClose={() => setIsAddMemberModalOpen(false)}
                onAdd={handleAddMember}
                currentMembers={members}
            />
        </div>
    );
};

export default GroupChatArea;
