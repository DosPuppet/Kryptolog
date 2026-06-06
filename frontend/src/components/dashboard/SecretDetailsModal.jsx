import { useState, useEffect, useCallback } from 'react';
import { X, Clock, User, Trash2, Loader2, Info } from 'lucide-react';
import API_ENDPOINTS from '../../config';
import { useAuth } from '../../context/AuthContext';

const SecretDetailsModal = ({ isOpen, onClose, secret }) => {
    const { token } = useAuth();
    const [loading, setLoading] = useState(false);
    const [grants, setGrants] = useState([]);
    const [error, setError] = useState(null);

    const fetchGrants = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(API_ENDPOINTS.SECRETS.ACCESS(secret.id), {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setGrants(data);
            } else {
                throw new Error("Failed to load access details");
            }
        } catch (err) {
            console.error(err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }, [token, secret]);

    useEffect(() => {
        if (isOpen && secret) {
            fetchGrants();
        } else {
            setGrants([]);
        }
    }, [isOpen, secret, fetchGrants]);

    const handleRevoke = async (grantId) => {
        if (!confirm("Are you sure you want to revoke access?")) return;

        try {
            const res = await fetch(API_ENDPOINTS.SECRETS.REVOKE(grantId), {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                setGrants(grants.filter(g => g.id !== grantId));
            } else {
                alert("Failed to revoke access");
            }
        } catch (e) {
            alert("Error revoking access");
        }
    };

    const calculateTimeRemaining = (expiresAt) => {
        if (!expiresAt) return "Permanent";
        const now = new Date();
        const end = new Date(expiresAt);
        const diff = end - now;

        if (diff <= 0) return "Expired";

        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-in fade-in duration-200">
            <div className="bg-white dark:bg-slate-850 rounded-2xl shadow-xl w-full max-w-lg border border-slate-200 dark:border-slate-700 overflow-hidden flex flex-col max-h-[80vh]">

                {/* Header */}
                <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center bg-slate-50 dark:bg-slate-850/50">
                    <div className="flex items-center gap-2">
                        <Info className="w-5 h-5 text-indigo-500" />
                        <h3 className="font-bold text-lg text-slate-900 dark:text-white">Secret Details</h3>
                    </div>
                    <button onClick={onClose} className="p-1 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-full transition-colors">
                        <X className="w-5 h-5 text-slate-500" />
                    </button>
                </div>

                {/* Content */}
                <div className="p-6 overflow-y-auto flex-1">
                    <div className="mb-6">
                        <h4 className="text-sm font-medium text-slate-500 uppercase mb-1">Secret Name</h4>
                        <p className="text-lg font-semibold text-slate-900 dark:text-white">{secret?.name}</p>
                    </div>

                    <h4 className="text-sm font-medium text-slate-500 uppercase mb-3 flex items-center gap-2">
                        Shared With <span className="bg-indigo-100 dark:bg-indigo-900 text-indigo-600 dark:text-indigo-400 text-xs px-2 py-0.5 rounded-full">{grants.length}</span>
                    </h4>

                    {loading ? (
                        <div className="flex justify-center py-8">
                            <Loader2 className="w-6 h-6 animate-spin text-indigo-500" />
                        </div>
                    ) : error ? (
                        <div className="text-red-500 text-center py-4">{error}</div>
                    ) : grants.length === 0 ? (
                        <div className="text-center py-8 text-slate-400 border-2 border-dashed border-slate-100 dark:border-slate-700 rounded-xl">
                            No active shares.
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {grants.map(grant => (
                                <div key={grant.id} className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-750/50 rounded-lg border border-slate-100 dark:border-slate-700">
                                    <div className="flex items-center gap-3 overflow-hidden">
                                        <div className="w-8 h-8 rounded-full bg-indigo-100 dark:bg-indigo-900 flex items-center justify-center shrink-0">
                                            <User className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                                        </div>
                                        <div className="min-w-0">
                                            <p className="font-medium text-sm text-slate-900 dark:text-white truncate" title={grant.grantee?.username || grant.grantee_address}>
                                                {grant.grantee?.username || "Unknown User"}
                                            </p>
                                            <p className="text-xs text-slate-500 font-mono truncate w-32 md:w-48">
                                                {grant.grantee_address}
                                            </p>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-3">
                                        <div className="text-right">
                                            <div className="flex items-center gap-1 text-xs text-slate-500 justify-end">
                                                <Clock className="w-3 h-3" />
                                                <span>{calculateTimeRemaining(grant.expires_at)}</span>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => handleRevoke(grant.id)}
                                            className="p-1.5 hover:bg-red-100 dark:hover:bg-red-900/30 text-slate-400 hover:text-red-500 rounded transition-colors"
                                            title="Revoke Access"
                                        >
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SecretDetailsModal;
