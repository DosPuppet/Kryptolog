import React, { useState, useEffect } from 'react';
import { X, Search, Loader2, Users, Plus, Check } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import API_ENDPOINTS from '../../config';

const CreateGroupModal = ({ isOpen, onClose, onCreate }) => {
    const { user } = useAuth();
    const [groupName, setGroupName] = useState('');
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState([]);
    const [selectedMembers, setSelectedMembers] = useState([]);
    const [searching, setSearching] = useState(false);
    const [creating, setCreating] = useState(false);

    const searchUsers = async (query) => {
        setSearching(true);
        try {
            const res = await fetch(`${API_ENDPOINTS.USERS.LIST}?search=${encodeURIComponent(query)}&only_pqc=true&limit=10`);
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

    useEffect(() => {
        if (!isOpen) {
            setGroupName('');
            setSearchQuery('');
            setSearchResults([]);
            setSelectedMembers([]);
        }
    }, [isOpen]);

    const toggleMember = (u) => {
        setSelectedMembers(prev => {
            const exists = prev.find(m => m.address === u.address);
            if (exists) return prev.filter(m => m.address !== u.address);
            return [...prev, u];
        });
    };

    const handleCreate = async () => {
        if (!groupName.trim() || selectedMembers.length === 0) return;
        setCreating(true);
        try {
            await onCreate(groupName.trim(), selectedMembers.map(m => m.address));
            onClose();
        } catch (e) {
            alert("Failed to create group: " + e.message);
        } finally {
            setCreating(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 w-full max-w-md animate-in fade-in zoom-in-95 flex flex-col max-h-[85vh]">
                <div className="flex justify-between items-center mb-6 shrink-0">
                    <h3 className="text-xl font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <Users className="w-5 h-5 text-indigo-500" /> New Group
                    </h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Group Name */}
                <div className="mb-4">
                    <input
                        type="text"
                        value={groupName}
                        onChange={(e) => setGroupName(e.target.value)}
                        className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none"
                        placeholder="Group name..."
                        autoFocus
                        maxLength={100}
                    />
                </div>

                {/* Selected Members */}
                {selectedMembers.length > 0 && (
                    <div className="mb-3 flex flex-wrap gap-2">
                        {selectedMembers.map(m => (
                            <button
                                key={m.address}
                                onClick={() => toggleMember(m)}
                                className="flex items-center gap-1 bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 px-2 py-1 rounded-full text-xs font-medium hover:bg-indigo-200 dark:hover:bg-indigo-900/50 transition-colors"
                            >
                                {m.username || `${m.address.substring(0, 8)}...`}
                                <X className="w-3 h-3" />
                            </button>
                        ))}
                    </div>
                )}

                {/* Search */}
                <div className="mb-4">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg pl-10 pr-4 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none"
                            placeholder="Search members to add..."
                        />
                    </div>
                </div>

                {/* Search Results */}
                <div className="flex-1 overflow-y-auto min-h-[150px] mb-4">
                    {searching ? (
                        <div className="flex justify-center p-6">
                            <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
                        </div>
                    ) : searchResults.length === 0 ? (
                        <div className="text-center py-6 text-slate-500 text-sm">
                            {searchQuery ? "No users found" : "Search for users to add"}
                        </div>
                    ) : (
                        <div className="space-y-1">
                            {searchResults.map(u => {
                                const isSelected = selectedMembers.some(m => m.address === u.address);
                                return (
                                    <button
                                        key={u.address}
                                        onClick={() => toggleMember(u)}
                                        className={`w-full p-3 rounded-lg flex items-center gap-3 transition-colors text-left ${isSelected ? 'bg-indigo-50 dark:bg-indigo-900/20' : 'hover:bg-slate-100 dark:hover:bg-slate-700'}`}
                                    >
                                        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-white font-bold shrink-0">
                                            {(u.username || u.address).substring(0, 1).toUpperCase()}
                                        </div>
                                        <div className="flex-1 overflow-hidden">
                                            <div className="font-medium text-slate-900 dark:text-white truncate">
                                                {u.username || `${u.address.substring(0, 8)}...`}
                                            </div>
                                            <div className="text-xs text-slate-500 font-mono truncate">{u.address}</div>
                                        </div>
                                        {isSelected && (
                                            <Check className="w-5 h-5 text-indigo-600 dark:text-indigo-400 shrink-0" />
                                        )}
                                    </button>
                                );
                            })}
                        </div>
                    )}
                </div>

                {/* Create Button */}
                <button
                    onClick={handleCreate}
                    disabled={!groupName.trim() || selectedMembers.length === 0 || creating}
                    className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-indigo-500/20 flex items-center justify-center gap-2"
                >
                    {creating ? (
                        <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                        <>
                            <Plus className="w-5 h-5" />
                            Create Group ({selectedMembers.length} member{selectedMembers.length !== 1 ? 's' : ''})
                        </>
                    )}
                </button>
            </div>
        </div>
    );
};

export default CreateGroupModal;
