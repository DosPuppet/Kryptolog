import { useState, useEffect, useCallback } from 'react';
import { Search, Loader2, X, Check } from 'lucide-react';
import API_ENDPOINTS from '../../config';
import { useAuth } from '../../context/AuthContext';

const ShareModal = ({ isOpen, onClose, secret, onShare }) => {
    const { token, user } = useAuth();
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const [sharing, setSharing] = useState(false);
    const [selectedUser, setSelectedUser] = useState(null);
    const [expiry, setExpiry] = useState(0);
    // Inline feedback instead of window.alert(): blocking dialogs are unreliable
    // in installed PWAs (notably iOS standalone), where they can be suppressed or
    // hang — leaving the modal stuck open even though the share succeeded.
    const [error, setError] = useState('');
    const [successMsg, setSuccessMsg] = useState('');

    const searchUsers = useCallback(async (query) => {
        setLoading(true);
        try {
            const limit = 10;
            const url = query
                ? `${API_ENDPOINTS.USERS.LIST}?search=${encodeURIComponent(query)}&limit=${limit}`
                : `${API_ENDPOINTS.USERS.LIST}?limit=${limit}`;
            const res = await fetch(url, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await res.json();
            setSearchResults(data.filter(u => u.address !== user.address));
        } catch (error) {
            console.error("Search failed", error);
        } finally {
            setLoading(false);
        }
    }, [token, user]);

    // Debounce
    useEffect(() => {
        if (!isOpen) {
            setSearchQuery('');
            setSearchResults([]);
            setSelectedUser(null);
            setError('');
            setSuccessMsg('');
            return;
        }
        const timer = setTimeout(() => searchUsers(searchQuery), 500);
        return () => clearTimeout(timer);
    }, [searchQuery, isOpen, searchUsers]);

    const handleShare = async () => {
        if (!selectedUser || !secret) return;
        setSharing(true);
        setError('');
        try {
            const success = await onShare(secret.id, secret.encrypted_key, selectedUser.address, selectedUser.encryption_public_key, expiry);
            if (success) {
                // Show a brief inline confirmation, then auto-close (no blocking alert).
                setSuccessMsg(`Shared with ${selectedUser.username || 'recipient'}!`);
                setTimeout(() => onClose(), 1200);
            } else {
                setError("Share failed. Please try again.");
            }
        } catch (e) {
            setError(e.message || "Share failed.");
        } finally {
            setSharing(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 w-full max-w-md animate-in fade-in zoom-in-95 flex flex-col max-h-[85vh]">
                <div className="flex justify-between items-center mb-6 shrink-0">
                    <h3 className="text-xl font-semibold text-slate-900 dark:text-white">Share "{secret?.name}"</h3>
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

                <div className="flex-1 overflow-y-auto min-h-[200px] mb-4 border border-slate-100 dark:border-slate-700 rounded-lg p-1">
                    {loading ? (
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
                                    onClick={() => setSelectedUser(u)}
                                    className={`w-full p-3 rounded-lg flex items-center gap-3 transition-colors text-left ${selectedUser?.address === u.address ? 'bg-indigo-50 dark:bg-indigo-900/30' : 'hover:bg-slate-100 dark:hover:bg-slate-700'}`}
                                >
                                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-white font-bold shrink-0">
                                        {(u.username || u.address).substring(0, 1).toUpperCase()}
                                    </div>
                                    <div className="overflow-hidden flex-1">
                                        <div className="font-medium text-slate-900 dark:text-white truncate">
                                            {u.username || `${u.address.substring(0, 8)}...`}
                                        </div>
                                        <div className="text-xs text-slate-500 font-mono truncate">
                                            {u.address}
                                        </div>
                                    </div>
                                    {selectedUser?.address === u.address && <Check className="w-5 h-5 text-indigo-500" />}
                                </button>
                            ))}
                        </div>
                    )}
                </div>

                {selectedUser && (
                    <div className="animate-in slide-in-from-bottom-2">
                        <div className="mb-4">
                            <label className="block text-sm font-medium text-slate-500 mb-1">Access Expiry (Optional)</label>
                            <select
                                value={expiry}
                                onChange={e => setExpiry(Number(e.target.value))}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm"
                            >
                                <option value={0}>No Expiry (Permanent)</option>
                                <option value={3600}>1 Hour</option>
                                <option value={86400}>24 Hours</option>
                                <option value={604800}>7 Days</option>
                            </select>
                        </div>
                        <button
                            onClick={handleShare}
                            disabled={sharing || !!successMsg}
                            className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-2 rounded-lg font-medium shadow-lg shadow-indigo-500/20 disabled:opacity-50 flex justify-center items-center gap-2"
                        >
                            {sharing ? <Loader2 className="w-5 h-5 animate-spin" /> : `Share with ${selectedUser.username}`}
                        </button>
                    </div>
                )}

                {successMsg && (
                    <div className="mt-3 flex items-center gap-2 text-sm text-green-600 dark:text-green-400 shrink-0">
                        <Check className="w-4 h-4" /> {successMsg}
                    </div>
                )}
                {error && (
                    <div className="mt-3 text-sm text-red-600 dark:text-red-400 shrink-0">
                        {error}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ShareModal;
