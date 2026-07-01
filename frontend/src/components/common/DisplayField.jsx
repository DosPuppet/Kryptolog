import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

const DisplayField = ({ label, value }) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = () => {
        if (!value) return;
        navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    // Force truncation logic
    const shouldTruncate = value && value.length > 20;
    const displayValue = shouldTruncate
        ? `${value.substring(0, 8)}...${value.substring(value.length - 8)}`
        : value;

    return (
        <div>
            <label className="block text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">{label}</label>
            <div className="flex gap-2">
                <div className="flex-1 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-600 dark:text-slate-500 font-mono text-xs break-all flex items-center">
                    {displayValue || "Not set"}
                </div>
                <button
                    type="button"
                    onClick={handleCopy}
                    className="p-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-slate-400 hover:text-white transition-colors"
                    title="Copy to clipboard"
                >
                    {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                </button>
            </div>
        </div>
    );
};

export default DisplayField;
