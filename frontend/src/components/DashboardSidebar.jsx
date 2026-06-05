import React from 'react';
import { NavLink } from 'react-router-dom';
import { useMessenger } from '../hooks/useMessenger';
import { Lock, LockKeyhole, FolderGit2, Bell, BellOff, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNotifications } from '../context/NotificationContext';
import { vaultService } from '../services/vault';
import { API_ENDPOINTS } from '../config';

// Persisted set of shared-secret ids the user has already opened, so the "unread"
// badge stays cleared once read (instead of reappearing every time secrets re-lock).
const READ_SHARED_KEY = 'kryptolog_read_shared';
const loadReadShared = () => {
    try { return new Set(JSON.parse(localStorage.getItem(READ_SHARED_KEY) || '[]')); }
    catch { return new Set(); }
};

export default function DashboardSidebar({
    currentView,
    secrets,
    workflows,
    sharedSecrets,
    decryptedSecrets,
    actionRequiredCount,
    onRefreshSecrets
}) {
    // Only this component will re-render when messenger events occur (typing, new message)
    const { unreadCount, lastEvent } = useMessenger();
    const { authType, token } = useAuth();
    const { permission, subscription, error, requestPermission, unsubscribe } = useNotifications();

    // Listen for Real-time Events safely within this isolated component
    const lastProcessedEventId = React.useRef(null);

    React.useEffect(() => {
        if (lastEvent && lastEvent.type === 'SECRET_SHARED') {
            const eventId = lastEvent.message?.id || lastEvent.timestamp || JSON.stringify(lastEvent);

            if (lastProcessedEventId.current !== eventId) {
                console.log("Real-time Update: Secret Shared event received in Sidebar");
                lastProcessedEventId.current = eventId;
                if (onRefreshSecrets) {
                    onRefreshSecrets();
                }
            }
        }
    }, [lastEvent, onRefreshSecrets]);

    // Track which shared secrets have been opened at least once (sticky / persisted).
    const [readShared, setReadShared] = React.useState(loadReadShared);

    React.useEffect(() => {
        setReadShared(prev => {
            const currentIds = new Set(sharedSecrets.map(s => s.id));
            // Prune ids that are no longer shared with us.
            const next = new Set([...prev].filter(id => currentIds.has(id)));
            let changed = next.size !== prev.size;
            // Mark any currently-decrypted shared secret as read.
            for (const s of sharedSecrets) {
                if (decryptedSecrets[`shared_${s.id}`] && !next.has(s.id)) {
                    next.add(s.id);
                    changed = true;
                }
            }
            return changed ? next : prev;
        });
    }, [sharedSecrets, decryptedSecrets]);

    React.useEffect(() => {
        localStorage.setItem(READ_SHARED_KEY, JSON.stringify([...readShared]));
    }, [readShared]);

    const unreadSecrets = sharedSecrets.filter(s => !readShared.has(s.id)).length;

    const navItems = [
        { id: 'secrets', to: '/secrets', label: 'Secrets', icon: <Lock className="w-4 h-4" /> },
        { id: 'multisig', to: '/multisig', label: 'Multisig', icon: <FolderGit2 className="w-4 h-4" /> },
    ];

    const baseLinkClasses = "w-full flex items-center justify-between px-4 py-3 rounded-xl transition-all font-medium";
    const activeLinkClasses = "bg-indigo-600 text-white shadow-lg shadow-indigo-500/20";
    const inactiveLinkClasses = "text-slate-600 dark:text-slate-400 hover:bg-white dark:hover:bg-slate-900";

    return (
        <div className="lg:col-span-1 space-y-6">
            <nav className="space-y-1">
                {navItems.map(item => (
                    <NavLink
                        key={item.id}
                        to={item.to}
                        className={({ isActive }) =>
                            `${baseLinkClasses} ${isActive ? activeLinkClasses : inactiveLinkClasses}`
                        }
                    >
                        <div className="flex items-center gap-3">
                            {item.icon}
                            {item.label}
                        </div>
                        {item.id === 'multisig' && actionRequiredCount > 0 && (
                            <span className="bg-red-500 text-white text-xs font-bold px-2 py-0.5 rounded-full">
                                {actionRequiredCount}
                            </span>
                        )}
                        {item.id === 'secrets' && unreadSecrets > 0 && (
                            <span className="bg-red-500 text-white text-xs font-bold px-2 py-0.5 rounded-full">
                                {unreadSecrets}
                            </span>
                        )}
                    </NavLink>
                ))}
                {/* Messenger Tab - Only for TrustKeys/PQC users */}
                {authType !== 'metamask' && (
                    <NavLink
                        to="/messenger"
                        className={({ isActive }) =>
                            `${baseLinkClasses} ${isActive ? activeLinkClasses : inactiveLinkClasses}`
                        }
                    >
                        <div className="flex items-center gap-3">
                            <span className="text-lg">💬</span> Messenger
                        </div>
                        {unreadCount > 0 && (
                            <span className="bg-red-500 text-white text-xs font-bold px-2 py-0.5 rounded-full">
                                {unreadCount}
                            </span>
                        )}
                    </NavLink>
                )}
                <NavLink
                    to="/proof-audit"
                    className={({ isActive }) =>
                        `${baseLinkClasses} ${isActive ? activeLinkClasses : inactiveLinkClasses}`
                    }
                >
                    <div className="flex items-center gap-3">
                        <ShieldCheck className="w-4 h-4" /> Proof Audit
                    </div>
                </NavLink>
            </nav>

            {/* Lock Vault button — visible for local vault users when key cache is active */}
            {authType === 'trustkeys' && !window.trustkeys && vaultService.getCacheTTL() > 0 && (
                <button
                    onClick={() => {
                        vaultService.clearKeyCache();
                    }}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 hover:bg-amber-100 dark:hover:bg-amber-900/40 transition-colors"
                >
                    <LockKeyhole className="w-4 h-4" />
                    Lock Vault
                </button>
            )}

            {/* Quick Stats or Info */}
            <div className="bg-white dark:bg-slate-850 p-5 rounded-xl border border-slate-200 dark:border-slate-700">
                <h4 className="font-bold text-slate-900 dark:text-white mb-4 text-sm uppercase tracking-wider">Storage</h4>
                <div className="space-y-3">
                    <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Secrets</span>
                        <span className="font-medium text-slate-900 dark:text-white">{secrets.length}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Multisig</span>
                        <span className="font-medium text-slate-900 dark:text-white">{workflows.length}</span>
                    </div>
                </div>
            </div>

            {/* Notification Status */}
            <div className="bg-white dark:bg-slate-850 p-5 rounded-xl border border-slate-200 dark:border-slate-700">
                <div className="flex items-center justify-between mb-4">
                    <h4 className="font-bold text-slate-900 dark:text-white text-sm uppercase tracking-wider">Notifications</h4>
                    {permission === 'granted' ? (
                        <Bell className="w-4 h-4 text-emerald-500" />
                    ) : (
                        <BellOff className="w-4 h-4 text-amber-500" />
                    )}
                </div>
                <div className="space-y-3">
                    {permission === 'default' && (
                        <button
                            onClick={requestPermission}
                            className="w-full py-2 px-4 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-medium transition-colors"
                        >
                            Enable Push
                        </button>
                    )}
                    {permission === 'granted' && subscription ? (
                        <div className="space-y-2">
                            <p className="text-xs text-emerald-500 font-medium">Notifications Enabled</p>
                            <button
                                onClick={async () => {
                                    try {
                                        const res = await fetch(API_ENDPOINTS.NOTIFICATIONS.TEST, {
                                            method: 'POST',
                                            headers: { 'Authorization': `Bearer ${token}` }
                                        });
                                        const data = await res.json();
                                        if (data.status === 'no_subscriptions') alert(data.message);
                                    } catch (e) { console.error('Test push failed:', e); }
                                }}
                                className="w-full py-2 px-4 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-medium transition-colors"
                            >
                                🔔 Test Push
                            </button>
                            <button
                                onClick={unsubscribe}
                                className="w-full py-2 px-4 bg-slate-100 dark:bg-slate-750 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 rounded-lg text-xs font-medium transition-colors"
                            >
                                Disable Push
                            </button>
                        </div>
                    ) : permission === 'granted' ? (
                        <div className="space-y-2">
                            <p className="text-xs text-slate-500">Permission granted but not subscribed.</p>
                            <button
                                onClick={requestPermission} // Re-run subscribe logic
                                className="w-full py-2 px-4 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-medium transition-colors"
                            >
                                Enable Push
                            </button>
                        </div>
                    ) : permission === 'denied' ? (
                        <p className="text-xs text-red-500 font-medium">Notifications Blocked</p>
                    ) : (
                        <p className="text-xs text-slate-500">Enable to stay updated in real-time.</p>
                    )}

                    {error && (
                        <p className="text-xs text-red-500 mt-2 border-t pt-2 border-slate-200 dark:border-slate-600">
                            {error}
                        </p>
                    )}
                </div>
            </div>
        </div>
    );
}
