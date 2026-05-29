import React from 'react';

const GlobalProgressBar = ({ progress, message }) => {
    if (progress <= 0) return null;

    return (
        <div className="fixed top-0 left-0 right-0 z-[100]">
            <div className="h-1 w-full bg-slate-200 dark:bg-slate-750">
                <div
                    className="h-full bg-indigo-600 transition-all duration-300 ease-out shadow-[0_0_10px_rgba(79,70,229,0.5)]"
                    style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
                />
            </div>
            {message && (
                <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-slate-900/90 text-white px-4 py-1.5 rounded-full text-xs font-medium backdrop-blur-sm shadow-lg animate-in slide-in-from-top-2 fade-in">
                    {message}
                </div>
            )}
        </div>
    );
};

export default GlobalProgressBar;
