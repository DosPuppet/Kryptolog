import React, { useState, useMemo } from 'react';
import { Loader2, FolderGit2, Check, Clock, AlertTriangle, LayoutGrid, List, ChevronDown, Eye } from 'lucide-react';

const MultisigList = ({ workflows, onSelect, onCreate, loading }) => {
    const [viewMode, setViewMode] = useState(() => localStorage.getItem('multisigViewMode') || 'grid');
    const [sortBy, setSortBy] = useState(() => localStorage.getItem('multisigSortBy') || 'date-desc');
    const [expandedId, setExpandedId] = useState(null);

    const handleViewChange = (mode) => {
        setViewMode(mode);
        localStorage.setItem('multisigViewMode', mode);
    };

    const handleSortChange = (value) => {
        setSortBy(value);
        localStorage.setItem('multisigSortBy', value);
    };

    const sortedWorkflows = useMemo(() => {
        const sorted = [...workflows];
        switch (sortBy) {
            case 'date-desc': sorted.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)); break;
            case 'date-asc': sorted.sort((a, b) => new Date(a.created_at) - new Date(b.created_at)); break;
            case 'name-asc': sorted.sort((a, b) => (a.name || '').localeCompare(b.name || '')); break;
            case 'name-desc': sorted.sort((a, b) => (b.name || '').localeCompare(a.name || '')); break;
            case 'initiator': sorted.sort((a, b) => (a.owner?.username || a.owner_address || '').localeCompare(b.owner?.username || b.owner_address || '')); break;
        }
        return sorted;
    }, [workflows, sortBy]);

    if (loading) {
        return (
            <div className="flex justify-center p-12">
                <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
            </div>
        );
    }

    if (workflows.length === 0) {
        return (
            <div className="text-center py-16 px-4 rounded-2xl border-2 border-dashed border-slate-200 dark:border-slate-700 animate-in fade-in zoom-in-95">
                <div className="w-16 h-16 bg-slate-100 dark:bg-slate-850 rounded-full flex items-center justify-center mx-auto mb-4">
                    <FolderGit2 className="w-8 h-8 text-slate-400" />
                </div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">No Workflows</h3>
                <p className="text-slate-500 mb-4">Create a multisig workflow to require multiple approvals.</p>
                <button
                    onClick={onCreate}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors"
                >
                    Create Workflow
                </button>
            </div>
        );
    }

    const toggleBtn = (mode, Icon) => (
        <button
            onClick={() => handleViewChange(mode)}
            className={`p-1.5 rounded-md transition-colors ${viewMode === mode
                ? 'bg-indigo-600 text-white'
                : 'bg-slate-100 dark:bg-slate-750 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
        >
            <Icon className="w-4 h-4" />
        </button>
    );

    const toolbar = (
        <div className="flex items-center justify-between mb-4">
            <select
                value={sortBy}
                onChange={(e) => handleSortChange(e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
                <option value="date-desc">Newest first</option>
                <option value="date-asc">Oldest first</option>
                <option value="name-asc">Name A–Z</option>
                <option value="name-desc">Name Z–A</option>
                <option value="initiator">Initiator A–Z</option>
            </select>
            <div className="flex items-center gap-1">
                {toggleBtn('grid', LayoutGrid)}
                {toggleBtn('list', List)}
            </div>
        </div>
    );

    const statusDot = (status) => {
        const color = status === 'completed' ? 'bg-emerald-500' : status === 'failed' ? 'bg-red-500' : 'bg-amber-500';
        return <span className={`w-2.5 h-2.5 rounded-full ${color} inline-block flex-shrink-0`} />;
    };

    const layoutClass = viewMode === 'grid'
        ? 'grid grid-cols-1 md:grid-cols-2 gap-4'
        : 'flex flex-col gap-2';

    return (
        <div>
            {toolbar}
            <div className={layoutClass}>
                {sortedWorkflows.map(wf => {
                    const completed = wf.signers.filter(s => s.has_signed).length;
                    const total = wf.signers.length;
                    const progress = (completed / total) * 100;
                    const initiator = wf.owner?.username || (wf.owner_address ? wf.owner_address.slice(0, 10) + '…' : '');

                    if (viewMode === 'list') {
                        const isExpanded = expandedId === wf.id;
                        return (
                            <div
                                key={wf.id}
                                className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-lg hover:shadow-md transition-all text-left"
                            >
                                <div
                                    className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                                    onClick={() => setExpandedId(isExpanded ? null : wf.id)}
                                >
                                    {statusDot(wf.status)}
                                    <span className="font-semibold text-slate-900 dark:text-white truncate flex-1 min-w-0">{wf.name}</span>
                                    <span className="text-xs text-slate-500 whitespace-nowrap hidden sm:block">
                                        {completed}/{total}
                                    </span>
                                    <div className="w-16 h-1.5 bg-slate-100 dark:bg-slate-750 rounded-full overflow-hidden hidden sm:block">
                                        <div
                                            className={`h-full ${wf.status === 'completed' ? 'bg-emerald-500' : 'bg-amber-500'}`}
                                            style={{ width: `${progress}%` }}
                                        />
                                    </div>
                                    {initiator && (
                                        <span className="text-xs text-slate-400 whitespace-nowrap hidden md:block">{initiator}</span>
                                    )}
                                    <span className="text-xs text-slate-400 whitespace-nowrap hidden sm:block">
                                        {new Date(wf.created_at).toLocaleDateString()}
                                    </span>
                                    <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                                </div>

                                {isExpanded && (
                                    <div className="px-4 pb-3 border-t border-slate-100 dark:border-slate-700 pt-3 animate-in fade-in slide-in-from-top-1">
                                        <div className="flex items-center justify-between mb-3">
                                            <div className="flex items-center gap-2">
                                                {wf.status === 'completed' ? (
                                                    <span className="px-2 py-0.5 bg-emerald-100 text-emerald-700 rounded-full text-xs font-bold flex items-center gap-1">
                                                        <Check className="w-3 h-3" /> Completed
                                                    </span>
                                                ) : wf.status === 'failed' ? (
                                                    <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full text-xs font-bold flex items-center gap-1">
                                                        <AlertTriangle className="w-3 h-3" /> Failed
                                                    </span>
                                                ) : (
                                                    <span className="px-2 py-0.5 bg-amber-100 text-amber-700 rounded-full text-xs font-bold flex items-center gap-1">
                                                        <Clock className="w-3 h-3" /> Pending
                                                    </span>
                                                )}
                                                <span className="text-xs text-slate-500">ID: {wf.id}</span>
                                            </div>
                                            <button
                                                onClick={(e) => { e.stopPropagation(); onSelect(wf); }}
                                                className="flex items-center gap-1 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium transition-colors"
                                            >
                                                <Eye className="w-3 h-3" /> Open Workflow
                                            </button>
                                        </div>

                                        <div className="space-y-1.5">
                                            {wf.signers.map((signer, idx) => (
                                                <div key={idx} className="flex items-center gap-2 text-sm">
                                                    {signer.has_signed ? (
                                                        <Check className="w-3.5 h-3.5 text-emerald-500" />
                                                    ) : (
                                                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                                                    )}
                                                    <span className={signer.has_signed ? 'text-slate-700 dark:text-slate-300' : 'text-slate-400'}>
                                                        {signer.user?.username || (signer.user_address ? signer.user_address.slice(0, 12) + '…' : `Signer ${idx + 1}`)}
                                                    </span>
                                                    <span className={`text-xs ${signer.has_signed ? 'text-emerald-500' : 'text-slate-400'}`}>
                                                        {signer.has_signed ? 'signed' : 'pending'}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>

                                        <div className="mt-3 h-1.5 bg-slate-100 dark:bg-slate-750 rounded-full overflow-hidden">
                                            <div
                                                className={`h-full transition-all duration-500 ${wf.status === 'completed' ? 'bg-emerald-500' : 'bg-amber-500'}`}
                                                style={{ width: `${progress}%` }}
                                            />
                                        </div>
                                    </div>
                                )}
                            </div>
                        );
                    }

                    return (
                        <button
                            key={wf.id}
                            onClick={() => onSelect(wf)}
                            className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-5 shadow-sm hover:shadow-md transition-all text-left group"
                        >
                            <div className="flex justify-between items-start mb-3">
                                <div>
                                    <h3 className="font-bold text-slate-900 dark:text-white group-hover:text-indigo-500 transition-colors">{wf.name}</h3>
                                    <p className="text-xs text-slate-500">ID: {wf.id}</p>
                                </div>
                                {wf.status === 'completed' ? (
                                    <span className="px-2 py-1 bg-emerald-100 text-emerald-700 rounded-full text-xs font-bold flex items-center gap-1">
                                        <Check className="w-3 h-3" /> Done
                                    </span>
                                ) : wf.status === 'failed' ? (
                                    <span className="px-2 py-1 bg-red-100 text-red-700 rounded-full text-xs font-bold flex items-center gap-1">
                                        <AlertTriangle className="w-3 h-3" /> Failed
                                    </span>
                                ) : (
                                    <span className="px-2 py-1 bg-amber-100 text-amber-700 rounded-full text-xs font-bold flex items-center gap-1">
                                        <Clock className="w-3 h-3" /> Pending
                                    </span>
                                )}
                            </div>

                            <div className="space-y-2">
                                <div className="flex justify-between text-xs text-slate-500">
                                    <span>Progress</span>
                                    <span>{completed}/{total} Signatures</span>
                                </div>
                                <div className="h-1.5 bg-slate-100 dark:bg-slate-750 rounded-full overflow-hidden">
                                    <div
                                        className={`h-full transition-all duration-500 ${wf.status === 'completed' ? 'bg-emerald-500' : 'bg-amber-500'}`}
                                        style={{ width: `${progress}%` }}
                                    />
                                </div>
                            </div>

                            <div className="mt-4 flex items-center gap-2 text-xs text-slate-400">
                                <span>Created {new Date(wf.created_at).toLocaleDateString()}</span>
                                <span>•</span>
                                <span>{wf.signers.length} Signers</span>
                            </div>
                        </button>
                    );
                })}
            </div>
        </div>
    );
};

export default MultisigList;
