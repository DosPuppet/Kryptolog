import React, { useState, useEffect, useRef } from 'react';

const PasswordModal = ({ isOpen, onSubmit, onCancel, message, onBiometric }) => {
    const [password, setPassword] = useState('');
    const inputRef = useRef(null);

    useEffect(() => {
        if (isOpen && inputRef.current) {
            setPassword('');
            inputRef.current.focus();
        }
    }, [isOpen]);

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        onSubmit(password);
        setPassword('');
    };

    const handleCancel = () => {
        onCancel();
        setPassword('');
    };

    return (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black bg-opacity-50">
            <div className="bg-white dark:bg-slate-850 rounded-lg shadow-xl p-6 w-full max-w-md mx-4">
                <h3 className="text-xl font-semibold mb-4 text-slate-900 dark:text-white">
                    Local Vault Security
                </h3>
                <p className="text-slate-600 dark:text-slate-300 mb-6">
                    {message || "Please enter your vault password to continue."}
                </p>

                <form onSubmit={handleSubmit}>
                    <div className="mb-6">
                        <input
                            ref={inputRef}
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="w-full px-4 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-750 text-slate-900 dark:text-white"
                            placeholder="Enter Password"
                            autoComplete="current-password"
                        />
                    </div>

                    <div className="flex justify-end space-x-3">
                        <button
                            type="button"
                            onClick={handleCancel}
                            className="px-4 py-2 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-md transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={!password}
                            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            Confirm
                        </button>
                    </div>
                </form>

                {onBiometric && (
                    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-600 flex justify-center">
                        <button
                            type="button"
                            onClick={onBiometric}
                            className="text-sm text-indigo-600 dark:text-indigo-400 hover:underline flex items-center gap-1"
                        >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.2-2.858.567-4.168" />
                            </svg>
                            Use FaceID / TouchID
                        </button>
                    </div>
                )}
            </div>
        </div >
    );
};

export default PasswordModal;
