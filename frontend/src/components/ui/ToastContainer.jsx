import { useEffect, useState } from 'react';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';
import { subscribeToasts, getToasts, dismissToast } from '../../utils/toast';

const STYLES = {
    success: { icon: CheckCircle2, cls: 'border-green-500/30 text-green-700 dark:text-green-300' },
    error: { icon: AlertCircle, cls: 'border-red-500/30 text-red-700 dark:text-red-300' },
    info: { icon: Info, cls: 'border-indigo-500/30 text-indigo-700 dark:text-indigo-300' },
};

const ToastContainer = () => {
    const [toasts, setToasts] = useState(getToasts());

    useEffect(() => subscribeToasts(setToasts), []);

    if (toasts.length === 0) return null;

    return (
        <div className="fixed top-4 left-1/2 -translate-x-1/2 z-[100] flex flex-col gap-2 w-[calc(100%-2rem)] max-w-sm pointer-events-none">
            {toasts.map((t) => {
                const { icon: Icon, cls } = STYLES[t.type] || STYLES.info;
                return (
                    <div
                        key={t.id}
                        role="status"
                        className={`pointer-events-auto flex items-start gap-3 bg-white dark:bg-slate-850 border ${cls} shadow-lg rounded-xl px-4 py-3 animate-in fade-in slide-in-from-top-2`}
                    >
                        <Icon className="w-5 h-5 shrink-0 mt-0.5" />
                        <p className="text-sm text-slate-900 dark:text-white flex-1 break-words">{t.message}</p>
                        <button
                            onClick={() => dismissToast(t.id)}
                            className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors shrink-0"
                            aria-label="Dismiss"
                        >
                            <X className="w-4 h-4" />
                        </button>
                    </div>
                );
            })}
        </div>
    );
};

export default ToastContainer;
