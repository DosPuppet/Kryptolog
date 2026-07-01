import { useState, useEffect } from 'react';
import { X, User, Key, Save, Loader2, Fingerprint } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { usePQC } from '../../context/PQCContext';
import API_ENDPOINTS from '../../config';
import DisplayField from '../common/DisplayField';
import { safetyNumber } from '../../utils/fingerprint';

const ProfileModal = ({ isOpen, onClose }) => {
    const { user, setUser, token } = useAuth();
    const { pqcAccount, kyberKey } = usePQC();

    const [username, setUsername] = useState(user?.username || '');
    const [updating, setUpdating] = useState(false);
    const [error, setError] = useState('');

    // PQC identity (ML-KEM encryption key + ML-DSA account id).
    const encryptionPublicKey = kyberKey;
    const accountId = pqcAccount;

    // Your verifiable safety number (audit S1) — read it out to a contact so
    // they can confirm the directory served them your real key.
    const [fingerprint, setFingerprint] = useState('');

    useEffect(() => {
        if (user?.username) setUsername(user.username);
    }, [user]);

    useEffect(() => {
        let cancelled = false;
        safetyNumber(accountId, encryptionPublicKey).then((fp) => {
            if (!cancelled) setFingerprint(fp || '');
        });
        return () => { cancelled = true; };
    }, [accountId, encryptionPublicKey]);

    const handleUpdateProfile = async (e) => {
        e.preventDefault();
        setUpdating(true);
        setError('');
        try {
            const res = await fetch(API_ENDPOINTS.USERS.UPDATE(user.address), {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    username: username
                })
            });

            if (res.ok) {
                const updatedUser = await res.json();
                setUser(updatedUser);
                onClose();
            } else {
                const data = await res.json().catch(() => null);
                setError(data?.detail || "Failed to update profile");
            }
        } catch (err) {
            console.error("Failed to update profile", err);
            setError("Failed to update profile");
        } finally {
            setUpdating(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 w-full max-w-md animate-in fade-in zoom-in-95">
                <div className="flex justify-between items-center mb-6">
                    <h3 className="text-xl font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <User className="w-5 h-5 text-indigo-500" /> User Profile
                    </h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                <form onSubmit={handleUpdateProfile} className="space-y-6">
                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Username</label>
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 outline-none"
                                placeholder="Set a username"
                            />
                            {error && (
                                <p className="text-red-500 text-sm mt-1">{error}</p>
                            )}
                        </div>

                        <div className="border-t border-slate-100 dark:border-slate-700 pt-4 space-y-4">
                            <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                <Key className="w-4 h-4" /> Keys & Identity
                            </h4>

                            <DisplayField label="Account Address (ID)" value={accountId} />
                            <DisplayField label="Encryption Public Key" value={encryptionPublicKey} />

                            {fingerprint && (
                                <div>
                                    <label className="flex items-center gap-1.5 text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">
                                        <Fingerprint className="w-4 h-4" /> Safety number
                                    </label>
                                    <div className="font-mono text-sm text-slate-900 dark:text-white tracking-wide break-all bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2">
                                        {fingerprint}
                                    </div>
                                    <p className="text-[11px] text-slate-400 mt-1">Read this to a contact so they can verify they have your real key.</p>
                                </div>
                            )}
                        </div>
                    </div>

                    <div className="flex gap-3 pt-2">
                        <button
                            type="button"
                            onClick={onClose}
                            className="flex-1 px-4 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                        >
                            Close
                        </button>
                        <button
                            type="submit"
                            disabled={updating}
                            className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg font-medium shadow-lg shadow-indigo-500/20 disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                            {updating ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Save className="w-4 h-4" /> Save Attributes</>}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ProfileModal;
