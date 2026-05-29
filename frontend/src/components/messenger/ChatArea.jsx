import React, { useState, useEffect, useRef } from 'react';
import { ArrowLeft, Shield, Loader2, Send, Lock, MessageSquare } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

const ChatArea = ({ activeConversation, onBack, onSend, loadingMessages, sending, onDecrypt }) => {
    const { user } = useAuth();
    const [inputText, setInputText] = useState('');
    const messagesEndRef = useRef(null);

    // Scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [activeConversation?.messages]);

    const handleSend = (e) => {
        e.preventDefault();
        if (!inputText.trim()) return;
        onSend(inputText, activeConversation.user);
        setInputText('');
    };

    if (!activeConversation) {
        return (
            <div className="hidden md:flex flex-1 flex-col items-center justify-center text-slate-400 p-8 bg-slate-50 dark:bg-slate-900">
                <div className="w-20 h-20 bg-slate-100 dark:bg-slate-750 rounded-full flex items-center justify-center mb-4">
                    <MessageSquare className="w-10 h-10 text-slate-300 dark:text-slate-600" />
                </div>
                <p>Select a conversation to start chatting</p>
            </div>
        );
    }

    return (
        <div className="flex flex-1 flex-col bg-slate-50 dark:bg-slate-900 h-full">
            {/* Header */}
            <div className="p-4 bg-white dark:bg-slate-850 border-b border-slate-200 dark:border-slate-700 flex items-center gap-3 shadow-sm z-10">
                <button
                    onClick={onBack}
                    className="md:hidden p-2 -ml-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-full"
                >
                    <ArrowLeft className="w-5 h-5 dark:text-white" />
                </button>
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-white font-bold shadow-sm">
                    {(activeConversation.user.username || activeConversation.user.address).substring(0, 1).toUpperCase()}
                </div>
                <div>
                    <h3 className="font-bold text-slate-900 dark:text-white">
                        {activeConversation.user.username || `${activeConversation.user.address.substring(0, 8)}...`}
                    </h3>
                    <div className="flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                        <Shield className="w-3 h-3" /> End-to-End Encrypted
                    </div>
                </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {loadingMessages ? (
                    <div className="flex justify-center p-8">
                        <Loader2 className="w-8 h-8 animate-spin text-slate-400" />
                    </div>
                ) : (
                    activeConversation.messages.map(msg => {
                        const isMe = msg.sender_address === user.address;
                        return (
                            <div key={msg.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
                                <div className={`
                                    max-w-[80%] rounded-2xl px-4 py-3 shadow-sm transition-all
                                    ${isMe
                                        ? 'bg-indigo-600 text-white rounded-br-none'
                                        : 'bg-white dark:bg-slate-750 text-slate-800 dark:text-white rounded-bl-none border border-slate-200 dark:border-slate-600'}
                                `}>
                                    {msg.plainText ? (
                                        <p className="text-sm">{msg.plainText}</p>
                                    ) : (
                                        <button
                                            onClick={() => onDecrypt(msg)}
                                            className={`flex items-center gap-2 text-sm font-semibold px-2 py-1 rounded bg-black/10 hover:bg-black/20 dark:bg-white/10 dark:hover:bg-white/20 transition-colors ${isMe ? 'text-white' : 'text-indigo-500 dark:text-indigo-400'}`}
                                        >
                                            <Lock className="w-4 h-4" /> Click to Decrypt
                                        </button>
                                    )}
                                    <div className={`text-[10px] mt-1 opacity-70 ${isMe ? 'text-indigo-100' : 'text-slate-400'}`}>
                                        {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                    </div>
                                </div>
                            </div>
                        );
                    })
                )}
                <div ref={messagesEndRef} />
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
        </div>
    );
};

export default ChatArea;
