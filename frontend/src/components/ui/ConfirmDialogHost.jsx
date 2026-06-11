import { useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { subscribeConfirm, getConfirmState, resolveConfirm } from '../../utils/confirm';

const ConfirmDialogHost = () => {
    const [state, setState] = useState(getConfirmState());

    useEffect(() => subscribeConfirm(setState), []);

    // Allow Escape to cancel while open.
    useEffect(() => {
        if (!state) return;
        const onKey = (e) => {
            if (e.key === 'Escape') resolveConfirm(false);
            if (e.key === 'Enter') resolveConfirm(true);
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [state]);

    if (!state) return null;

    const { title, message, confirmText, cancelText, danger } = state;

    return (
        <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[110] p-4"
            onClick={() => resolveConfirm(false)}
        >
            <div
                className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 w-full max-w-sm animate-in fade-in zoom-in-95"
                onClick={(e) => e.stopPropagation()}
            >
                <div className="flex items-start gap-3 mb-4">
                    {danger && <AlertTriangle className="w-6 h-6 text-red-500 shrink-0 mt-0.5" />}
                    <div>
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{title}</h3>
                        {message && <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 break-words">{message}</p>}
                    </div>
                </div>
                <div className="flex gap-2 justify-end">
                    <button
                        onClick={() => resolveConfirm(false)}
                        className="px-4 py-2 rounded-lg text-sm font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
                    >
                        {cancelText}
                    </button>
                    <button
                        onClick={() => resolveConfirm(true)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium text-white shadow-lg transition-colors ${
                            danger
                                ? 'bg-red-600 hover:bg-red-500 shadow-red-500/20'
                                : 'bg-indigo-600 hover:bg-indigo-500 shadow-indigo-500/20'
                        }`}
                    >
                        {confirmText}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ConfirmDialogHost;
