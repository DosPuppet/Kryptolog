import React, { useState, useEffect } from 'react';
import { useWeb3 } from '../context/Web3Context';
import { usePQC } from '../context/PQCContext';
import { useTheme } from '../context/ThemeContext';
import { Shield, Wallet, ArrowRight, Loader2, Sun, Moon, Lock, UserPlus, X } from 'lucide-react';

export default function Login() {
    const { login } = useWeb3();
    const { loginTrustKeys, loginLocalVault, createLocalVault, isExtensionAvailable, hasLocalVault, unlockWithBiometrics, hasBiometrics } = usePQC();
    const { theme, toggleTheme } = useTheme();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [activeMethod, setActiveMethod] = useState(null);

    // Local Vault UI State
    const [showVaultModal, setShowVaultModal] = useState(false);
    const [vaultMode, setVaultMode] = useState('unlock'); // 'unlock' | 'create'
    const [password, setPassword] = useState('');
    const [vaultName, setVaultName] = useState('');

    useEffect(() => {
        if (showVaultModal) {
            setVaultMode(hasLocalVault ? 'unlock' : 'create');
        }
    }, [showVaultModal, hasLocalVault]);

    const handleLogin = async (method) => {
        setError(null);
        if (method === 'trustkeys') {
            if (isExtensionAvailable) {
                setLoading(true);
                setActiveMethod('trustkeys');
                try {
                    await loginTrustKeys();
                } catch (err) {
                    console.error("Login error:", err);
                    setError(`Failed to login: ${err.message || 'Please try again.'} `);
                } finally {
                    setLoading(false);
                    setActiveMethod(null);
                }
            } else {
                // Open Local Vault Modal
                setShowVaultModal(true);
            }
        } else if (method === 'biometric') {
            setLoading(true);
            setActiveMethod('biometric');
            try {
                await unlockWithBiometrics();
            } catch (err) {
                console.error("Biometric Login error:", err);
                // Fail silently if not setup, just show modal
                if (!err.message.includes("Biometrics not set up")) {
                    setError(`Biometric failed: ${err.message}. Try password.`);
                }
                setShowVaultModal(true);
            } finally {
                setLoading(false);
                setActiveMethod(null);
            }
        } else {
            setLoading(true);
            setActiveMethod(method);
            try {
                await login();
            } catch (err) {
                console.error("Login error:", err);
                setError(`Failed to login: ${err.message || 'Please try again.'} `);
            } finally {
                setLoading(false);
                setActiveMethod(null);
            }
        }
    };

    const handleVaultSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        try {
            if (vaultMode === 'create') {
                if (!vaultName || !password) throw new Error("Name and Password required");
                if (password.length < 6) throw new Error("Password must be at least 6 characters");
                await createLocalVault(vaultName, password);
            } else {
                if (!password) throw new Error("Password required");
                await loginLocalVault(password);
            }
            setShowVaultModal(false);
        } catch (err) {
            console.error("Vault Action Error:", err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center p-4 transition-colors duration-200">
            <button
                onClick={toggleTheme}
                className="absolute top-4 right-4 p-2 rounded-lg bg-slate-200 dark:bg-slate-750 text-slate-700 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors"
            >
                {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            <div className="max-w-md w-full bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-2xl p-8 shadow-2xl transition-colors duration-200 relative">
                <div className="flex flex-col items-center text-center mb-8">
                    <div className="w-16 h-16 bg-indigo-50 dark:bg-indigo-500/10 rounded-full flex items-center justify-center mb-4">
                        <Shield className="w-8 h-8 text-indigo-600 dark:text-indigo-500" />
                    </div>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Kryptolog</h1>
                    <p className="text-slate-500 dark:text-slate-400">
                        Secret management and document signing.
                    </p>
                </div>

                {error && !showVaultModal && (
                    <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm text-center">
                        {error}
                    </div>
                )}

                <button
                    onClick={() => handleLogin('metamask')}
                    disabled={loading}
                    className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-200 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed group mb-4"
                >
                    {loading && activeMethod === 'metamask' ? (
                        <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                        <>
                            <Wallet className="w-5 h-5" />
                            <span>Connect with MetaMask</span>
                            <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                        </>
                    )}
                </button>

                {isExtensionAvailable ? (
                    <button
                        onClick={() => handleLogin('trustkeys')}
                        disabled={loading}
                        className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-200 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed group mt-4 shadow-lg shadow-emerald-500/20"
                    >
                        {loading && activeMethod === 'trustkeys' ? (
                            <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                            <>
                                <Shield className="w-5 h-5" />
                                <span>Connect with TrustKeys</span>
                                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                            </>
                        )}
                    </button>
                ) : (
                    <button
                        onClick={() => hasBiometrics ? handleLogin('biometric') : setShowVaultModal(true)}
                        disabled={loading}
                        className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-200 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed group mt-4 shadow-lg shadow-emerald-500/20"
                    >
                        {loading && (activeMethod === 'biometric' || showVaultModal) ? (
                            <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                            <>
                                {hasBiometrics ? (
                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.2-2.858.567-4.168" />
                                    </svg>
                                ) : (
                                    <Lock className="w-5 h-5" />
                                )}
                                <span>{hasLocalVault ? 'Unlock Local Vault' : 'Create Local Vault'}</span>
                                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                            </>
                        )}
                    </button>
                )}

                {/* Local Vault Modal Overlay */}
                {
                    showVaultModal && (
                        <div className="absolute inset-0 bg-white dark:bg-slate-850 rounded-2xl p-8 flex flex-col z-10 animate-in fade-in zoom-in-95">
                            <button
                                onClick={() => setShowVaultModal(false)}
                                className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                            >
                                <X className="w-5 h-5" />
                            </button>

                            <div className="flex flex-col items-center mb-6">
                                <div className="w-12 h-12 bg-emerald-500/10 rounded-full flex items-center justify-center mb-3">
                                    {vaultMode === 'create' ? <UserPlus className="w-6 h-6 text-emerald-500" /> : <Lock className="w-6 h-6 text-emerald-500" />}
                                </div>
                                <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                                    {vaultMode === 'create' ? 'Create Local Vault' : 'Unlock Vault'}
                                </h2>
                                <p className="text-sm text-slate-500 mt-1">
                                    {vaultMode === 'create'
                                        ? 'Setup a secure local PQC wallet.'
                                        : 'Enter password to access keys.'}
                                </p>
                            </div>

                            {error && (
                                <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-xs text-center">
                                    {error}
                                </div>
                            )}

                            <form onSubmit={handleVaultSubmit} className="space-y-4 flex-1">
                                {vaultMode === 'create' && (
                                    <div>
                                        <label className="block text-xs font-medium text-slate-500 mb-1">Account Name</label>
                                        <input
                                            type="text"
                                            value={vaultName}
                                            onChange={e => setVaultName(e.target.value)}
                                            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-emerald-500"
                                            placeholder="e.g. Main Account"
                                            autoFocus
                                        />
                                    </div>
                                )}
                                <div>
                                    <label className="block text-xs font-medium text-slate-500 mb-1">Password</label>
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={e => setPassword(e.target.value)}
                                        className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-emerald-500"
                                        placeholder="Enter secure password"
                                    />
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3 rounded-lg transition-all duration-200 mt-4 flex items-center justify-center"
                                >
                                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : (vaultMode === 'create' ? 'Create & Connect' : 'Unlock & Connect')}
                                </button>
                            </form>
                        </div>
                    )
                }
            </div >
        </div >
    );
}
