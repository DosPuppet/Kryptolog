import { useState, useEffect, useCallback } from 'react';
import { X, Search, Loader2, UserPlus, Check } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import API_ENDPOINTS from '../../config';

const AddMemberModal = ({ isOpen, onClose, onAdd, currentMembers = [] }) => {
    const { user, token } = useAuth();
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState([]);
    const [selectedUser, setSelectedUser] = useState(null);
    const [searching, setSearching] = useState(false);
    const [adding, setAdding] = useState(false);

    const searchUsers = useCallback(async (query) => {
        setSearching(true);
        try {
            const res = await fetch(`${API_ENDPOINTS.USERS.LIST}?search=${encodeURIComponent(query)}&only_pqc=true&limit=10`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await res.json();
            // Filter out self and existing members
            const filtered = data.filter(u =>
                u.address !== user.address &&
                !currentMembers.some(m => m.user_address === u.address)
            );
            setSearchResults(filtered);
        } catch (e) {
            console.error("Search failed", e);
        } finally {
            setSearching(false);
        }
    }, [token, user, currentMembers]);

    useEffect(() => {
        if (!isOpen) return;
        if (!searchQuery) { setSearchResults([]); return; }
        const timer = setTimeout(() => searchUsers(searchQuery), 500);
        return () => clearTimeout(timer);
    }, [searchQuery, isOpen, searchUsers]);

    useEffect(() => {
        if (!isOpen) {
            setSearchQuery('');
            setSearchResults([]);
            setSelectedUser(null);
        }
    }, [isOpen]);

    const handleAdd = async () => {
        if (!selectedUser) return;
        setAdding(true);
        try {
            await onAdd(selectedUser.address);
            onClose();
        } catch (e) {
            alert("Failed to add member: " + e.message);
        } finally {
            setAdding(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 w-full max-w-md animate-in fade-in zoom-in-95 flex flex-col max-h-[85vh]">
                <div className="flex justify-between items-center mb-6 shrink-0">
                    <h3 className="text-xl font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <UserPlus className="w-5 h-5 text-indigo-500" /> Add Member
                    </h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Selected User Preview */}
                {selectedUser && (
                    <div className="mb-4 p-3 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg flex items-center justify-between border border-indigo-100 dark:border-indigo-900/40">
                        <div className="flex items-center gap-3 overflow-hidden">
                            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-white font-bold shrink-0">
                                {(selectedUser.username || selectedUser.address).substring(0, 1).toUpperCase()}
                            </div>
                            <div className="flex-1 overflow-hidden">
                                <div className="font-medium text-slate-900 dark:text-white truncate">
                                    {selectedUser.username || `${selectedUser.address.substring(0, 8)}...`}
                                </div>
                            </div>
                        </div>
                        <button onClick={() => setSelectedUser(null)} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
                            <X className="w-4 h-4" />
                        </button>
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
                            placeholder="Search by username or address..."
                            autoFocus={!selectedUser}
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
                            {searchQuery ? "No users found" : "Search to find users"}
                        </div>
                    ) : (
                        <div className="space-y-1">
                            {searchResults.map(u => (
                                <button
                                    key={u.address}
                                    onClick={() => setSelectedUser(u)}
                                    className={`w-full p-3 rounded-lg flex items-center gap-3 transition-colors text-left ${selectedUser?.address === u.address ? 'bg-indigo-50 dark:bg-indigo-900/20 ring-1 ring-indigo-500' : 'hover:bg-slate-100 dark:hover:bg-slate-700'}`}
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
                                    {selectedUser?.address === u.address && (
                                        <Check className="w-5 h-5 text-indigo-600 dark:text-indigo-400 shrink-0" />
                                    )}
                                </button>
                            ))}
                        </div>
                    )}
                </div>

                {/* Add Button */}
                <button
                    onClick={handleAdd}
                    disabled={!selectedUser || adding}
                    className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-indigo-500/20 flex items-center justify-center gap-2"
                >
                    {adding ? (
                        <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                        <>
                            <UserPlus className="w-5 h-5" />
                            Add Member
                        </>
                    )}
                </button>
            </div>
        </div>
    );
};

export default AddMemberModal;
