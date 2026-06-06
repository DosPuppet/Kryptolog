import { useState, useEffect } from 'react';
import { usePQC } from '../context/PQCContext';
import { X, Plus, Trash2, Download, Upload, User, RefreshCw, Timer } from 'lucide-react';
import { vaultService } from '../services/vault';

export default function VaultManager({ onClose }) {
    const {
        getVaultAccounts,
        addVaultAccount,
        switchVaultAccount,
        deleteVaultAccount,
        exportVault,
        importVault,
        pqcAccount,
        manageBiometrics
    } = usePQC();

    const [accounts, setAccounts] = useState([]);
    const [view, setView] = useState('list'); // list | create | import
    const [newName, setNewName] = useState('');
    const [importJson, setImportJson] = useState('');
    const [msg, setMsg] = useState({ type: '', text: '' });

    const refresh = () => {
        setAccounts(getVaultAccounts());
    };

    // Refresh only when the active account changes. getVaultAccounts is a
    // stateless localStorage accessor, so it's intentionally not a dep.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    useEffect(() => { refresh(); }, [pqcAccount]);

    const handleCreate = async () => {
        try {
            if (!newName) return;
            await addVaultAccount(newName);
            setMsg({ type: 'success', text: 'Account created' });
            setNewName('');
            setView('list');
            refresh();
        } catch (e) {
            setMsg({ type: 'error', text: e.message });
        }
    };

    const handleSwitch = async (id) => {
        try {
            await switchVaultAccount(id);
            setMsg({ type: 'success', text: 'Switched. Logging out...' });
            setTimeout(onClose, 500);

        } catch (e) {
            setMsg({ type: 'error', text: e.message });
        }
    };

    const handleDelete = async (id) => {
        if (!confirm("Are you sure? This cannot be undone.")) return;
        try {
            await deleteVaultAccount(id);
            setMsg({ type: 'success', text: 'Account deleted' });
            refresh();
        } catch (e) {
            setMsg({ type: 'error', text: e.message });
        }
    };

    // Auto-lock timeout (derived key cache TTL)
    const [cacheTTL, setCacheTTL] = useState(() => vaultService.getCacheTTL());

    const handleTTLChange = (e) => {
        const val = parseInt(e.target.value, 10);
        setCacheTTL(val);
        vaultService.setCacheTTL(val);
    };

    // Biometrics
    const [hasBiometrics, setHasBiometrics] = useState(false);
    const [biometricMode, setBiometricMode] = useState(null); // 'prf' | 'fallback' | null

    useEffect(() => {
        const enabled = !!localStorage.getItem('kryptolog_biometrics');
        setHasBiometrics(enabled);
        if (enabled) {
            // Read mode from stored prefs
            try {
                const prefs = JSON.parse(localStorage.getItem('kryptolog_biometrics'));
                setBiometricMode(prefs.mode || 'prf');
            } catch { setBiometricMode('prf'); }
        }
    }, []);

    const toggleBiometrics = async () => {
        try {
            if (hasBiometrics) {
                if (confirm("Disable FaceID/TouchID unlock?")) {
                    await manageBiometrics(false);
                    setHasBiometrics(false);
                    setBiometricMode(null);
                    setMsg({ type: 'success', text: "Biometrics disabled" });
                }
            } else {
                // Always hardware-bound (PRF); throws on unsupported devices.
                const mode = await manageBiometrics(true);
                setHasBiometrics(true);
                setBiometricMode(mode);
                setMsg({ type: 'success', text: "Biometrics enabled! Hardware-bound key active." });
            }
        } catch (e) {
            setMsg({ type: 'error', text: e.message });
        }
    };

    const handleExport = async () => {
        try {
            const data = await exportVault();
            // Trigger download
            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `kryptolog-vault-${Date.now()}.json`;
            a.click();
            setMsg({ type: 'success', text: 'Vault exported' });
        } catch (e) {
            setMsg({ type: 'error', text: e.message });
        }
    };

    const handleImport = async () => {
        try {
            const count = await importVault(importJson);
            setMsg({ type: 'success', text: `Imported ${count} accounts` });
            setView('list');
            refresh();
        } catch (e) {
            setMsg({ type: 'error', text: e.message });
        }
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-slate-850 w-full max-w-lg rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col max-h-[80vh] mx-4">
                <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center">
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <User className="w-5 h-5" /> Local Vault Manager
                    </h2>
                    <button onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition">
                        <X className="w-5 h-5 text-slate-500" />
                    </button>
                </div>

                <div className="flex-1 overflow-y-auto p-4">
                    {msg.text && (
                        <div className={`mb-4 p-3 rounded-lg text-sm ${msg.type === 'error' ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'}`}>
                            {msg.text}
                        </div>
                    )}

                    {view === 'list' && (
                        <div className="space-y-3">
                            {accounts.map(acc => (
                                <div key={acc.id} className={`p-4 rounded-xl border flex items-center justify-between group transition-all ${acc.isActive ? 'border-emerald-500 bg-emerald-50/10' : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-700'}`}>
                                    <div>
                                        <div className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                                            {acc.name}
                                            {acc.isActive && <span className="text-xs bg-emerald-500 text-white px-2 py-0.5 rounded-full">Active</span>}
                                        </div>
                                        <div className="text-xs text-slate-500 font-mono mt-1">ID: {acc.id.substring(0, 8)}...</div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        {!acc.isActive && (
                                            <button
                                                onClick={() => handleSwitch(acc.id)}
                                                className="p-2 text-slate-500 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg"
                                                title="Switch to Account"
                                            >
                                                <RefreshCw className="w-4 h-4" />
                                            </button>
                                        )}
                                        <button
                                            onClick={() => handleDelete(acc.id)}
                                            className="p-2 text-slate-500 hover:text-red-600 hover:bg-red-50 rounded-lg"
                                            title="Delete Account"
                                        >
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    </div>
                                </div>
                            ))}

                            {/* Biometric Settings */}
                            <div className="pt-4 border-t border-slate-200 dark:border-slate-700">
                                <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-3">Security</h3>

                                {/* Security mode badge */}
                                {hasBiometrics && biometricMode === 'prf' && (
                                    <div className="mb-3 flex items-center gap-2 px-3 py-2 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg text-xs text-emerald-700 dark:text-emerald-300">
                                        <span>🔒</span>
                                        <span><strong>Hardware-Bound</strong>: Biometric key is secured in your device's hardware enclave.</span>
                                    </div>
                                )}
                                {hasBiometrics && biometricMode === 'fallback' && (
                                    <div className="mb-3 flex items-center gap-2 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg text-xs text-amber-700 dark:text-amber-300">
                                        <span>⚠️</span>
                                        <div>
                                            <strong>Insecure legacy mode — no longer supported</strong>: this biometric setup stored an unlock key in local storage and is being retired. Please <strong>disable</strong> biometric unlock and re-enable it (only hardware-bound devices are now supported), or just use your password.
                                        </div>
                                    </div>
                                )}

                                <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-700">
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 rounded-lg">
                                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.2-2.858.567-4.168" />
                                            </svg>
                                        </div>
                                        <div>
                                            <div className="font-medium text-slate-900 dark:text-white text-sm">Biometric Unlock</div>
                                            <div className="text-xs text-slate-500">FaceID / TouchID for quick access</div>
                                        </div>
                                    </div>
                                    <button
                                        onClick={toggleBiometrics}
                                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${hasBiometrics
                                            ? 'bg-red-100 text-red-700 hover:bg-red-200 dark:bg-red-900/30 dark:text-red-300'
                                            : 'bg-indigo-600 text-white hover:bg-indigo-500'
                                            }`}
                                    >
                                        {hasBiometrics ? 'Disable' : 'Enable'}
                                    </button>
                                </div>

                                {/* Auto-lock timeout (derived key cache) */}
                                <div className="mt-3 flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-700">
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 rounded-lg">
                                            <Timer className="w-5 h-5" />
                                        </div>
                                        <div>
                                            <div className="font-medium text-slate-900 dark:text-white text-sm">Auto-Lock Timeout</div>
                                            <div className="text-xs text-slate-500">Skip password prompt within window</div>
                                        </div>
                                    </div>
                                    <select
                                        value={cacheTTL}
                                        onChange={handleTTLChange}
                                        className="px-2 py-1.5 rounded-lg text-xs font-medium bg-white dark:bg-slate-750 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-amber-500"
                                    >
                                        <option value={0}>Always ask</option>
                                        <option value={60000}>1 minute</option>
                                        <option value={300000}>5 minutes</option>
                                        <option value={900000}>15 minutes</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    )}

                    {view === 'create' && (
                        <div className="space-y-4">
                            <h3 className="font-semibold dark:text-white">Create New Account</h3>
                            <input
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 outline-none focus:ring-2 focus:ring-emerald-500 dark:text-white"
                                placeholder="Account Name"
                                value={newName}
                                onChange={e => setNewName(e.target.value)}
                                autoFocus
                            />
                            <div className="flex gap-2">
                                <button onClick={handleCreate} className="flex-1 bg-emerald-600 text-white py-2 rounded-lg font-medium hover:bg-emerald-500">Create</button>
                                <button onClick={() => setView('list')} className="flex-1 bg-slate-200 dark:bg-slate-750 text-slate-700 dark:text-slate-300 py-2 rounded-lg font-medium">Cancel</button>
                            </div>
                        </div>
                    )}

                    {view === 'import' && (
                        <div className="space-y-4">
                            <h3 className="font-semibold dark:text-white">Import Vault (JSON)</h3>
                            <textarea
                                className="w-full h-32 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 outline-none focus:ring-2 focus:ring-emerald-500 text-xs font-mono dark:text-white"
                                placeholder="Paste JSON content here..."
                                value={importJson}
                                onChange={e => setImportJson(e.target.value)}
                            />
                            <div className="flex gap-2">
                                <button onClick={handleImport} className="flex-1 bg-emerald-600 text-white py-2 rounded-lg font-medium hover:bg-emerald-500">Import</button>
                                <button onClick={() => setView('list')} className="flex-1 bg-slate-200 dark:bg-slate-750 text-slate-700 dark:text-slate-300 py-2 rounded-lg font-medium">Cancel</button>
                            </div>
                        </div>
                    )}
                </div>

                <div className="p-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-850/50 rounded-b-2xl flex justify-between gap-2">
                    {view === 'list' && (
                        <>
                            <button onClick={() => setView('create')} className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-slate-750 border border-slate-200 dark:border-slate-600 rounded-lg text-sm hover:border-emerald-500 transition-colors dark:text-white">
                                <Plus className="w-4 h-4 text-emerald-500" /> New Account
                            </button>
                            <div className="flex gap-2">
                                <button onClick={handleExport} className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-slate-750 border border-slate-200 dark:border-slate-600 rounded-lg text-sm hover:border-indigo-500 transition-colors dark:text-white" title="Export Vault">
                                    <Download className="w-4 h-4 text-indigo-500" />
                                </button>
                                <button onClick={() => setView('import')} className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-slate-750 border border-slate-200 dark:border-slate-600 rounded-lg text-sm hover:border-indigo-500 transition-colors dark:text-white" title="Import Vault">
                                    <Upload className="w-4 h-4 text-indigo-500" />
                                </button>
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}
