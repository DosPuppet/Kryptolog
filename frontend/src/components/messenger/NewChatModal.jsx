import React, { useState, useEffect } from 'react';
import { X, Search, Loader2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import API_ENDPOINTS from '../../config';

const NewChatModal = ({ isOpen, onClose, onStartChat }) => {
    const { user, token } = useAuth();
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState([]);
    const [searching, setSearching] = useState(false);

    const searchUsers = async (query) => {
        setSearching(true);
        try {
            const res = await fetch(`${API_ENDPOINTS.USERS.LIST}?search=${encodeURIComponent(query)}&only_pqc=true&limit=10`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await res.json();
            setSearchResults(data.filter(u => u.address !== user.address));
        } catch (e) {
            console.error("Search failed", e);
        } finally {
            setSearching(false);
        }
    };

    useEffect(() => {
        if (!isOpen) return;
        if (!searchQuery) { setSearchResults([]); return; }
        const timer = setTimeout(() => searchUsers(searchQuery), 500);
        return () => clearTimeout(timer);
    }, [searchQuery, isOpen]);

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 w-full max-w-md animate-in fade-in zoom-in-95 flex flex-col max-h-[85vh]">
                <div className="flex justify-between items-center mb-6 shrink-0">
                    <h3 className="text-xl font-semibold text-slate-900 dark:text-white">New Chat</h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                <div className="mb-4">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg pl-10 pr-4 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none"
                            placeholder="Search by username or address..."
                            autoFocus
                        />
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto min-h-[200px]">
                    {searching ? (
                        <div className="flex justify-center p-8">
                            <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
                        </div>
                    ) : searchResults.length === 0 ? (
                        <div className="text-center py-8 text-slate-500 text-sm">
                            {searchQuery ? "No users found" : "Type to search users"}
                        </div>
                    ) : (
                        <div className="space-y-1">
                            {searchResults.map(u => (
                                <button
                                    key={u.address}
                                    onClick={() => onStartChat(u)}
                                    className="w-full p-3 rounded-lg flex items-center gap-3 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors text-left"
                                >
                                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-white font-bold shrink-0">
                                        {(u.username || u.address).substring(0, 1).toUpperCase()}
                                    </div>
                                    <div className="overflow-hidden">
                                        <div className="font-medium text-slate-900 dark:text-white truncate">
                                            {u.username || `${u.address.substring(0, 8)}...`}
                                        </div>
                                        <div className="text-xs text-slate-500 font-mono truncate">
                                            {u.address}
                                        </div>
                                    </div>
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default NewChatModal;
