import { useState, useMemo } from 'react';
import { Loader2, LayoutGrid, List } from 'lucide-react';
import SecretItem from './SecretItem';

const SecretList = ({ secrets, sharedSecrets = [], decryptedSecrets, onDecrypt, onLock, onDelete, onShare, onRevoke, onViewDetails, loading, authType }) => {
    const [viewMode, setViewMode] = useState(() => localStorage.getItem('secretViewMode') || 'grid');
    const [sortBy, setSortBy] = useState(() => localStorage.getItem('secretSortBy') || 'date-desc');

    const handleViewChange = (mode) => {
        setViewMode(mode);
        localStorage.setItem('secretViewMode', mode);
    };

    const handleSortChange = (value) => {
        setSortBy(value);
        localStorage.setItem('secretSortBy', value);
    };

    const sortItems = (items, getField) => {
        const sorted = [...items];
        switch (sortBy) {
            case 'date-desc': sorted.sort((a, b) => new Date(getField(b, 'created_at')) - new Date(getField(a, 'created_at'))); break;
            case 'date-asc': sorted.sort((a, b) => new Date(getField(a, 'created_at')) - new Date(getField(b, 'created_at'))); break;
            case 'name-asc': sorted.sort((a, b) => getField(a, 'name').localeCompare(getField(b, 'name'))); break;
            case 'name-desc': sorted.sort((a, b) => getField(b, 'name').localeCompare(getField(a, 'name'))); break;
        }
        return sorted;
    };

    const sortedSecrets = useMemo(() => sortItems(secrets, (s, f) => s[f] || ''), [secrets, sortBy]);
    const sortedShared = useMemo(() => sortItems(sharedSecrets, (g, f) => g.secret?.[f] || ''), [sharedSecrets, sortBy]);

    if (loading) {
        return (
            <div className="flex justify-center p-12">
                <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
            </div>
        );
    }

    if (secrets.length === 0 && sharedSecrets.length === 0) {
        return (
            <div className="text-center py-16 px-4 rounded-2xl border-2 border-dashed border-slate-200 dark:border-slate-700 animate-in fade-in zoom-in-95">
                <div className="w-16 h-16 bg-slate-100 dark:bg-slate-850 rounded-full flex items-center justify-center mx-auto mb-4">
                    <span className="text-2xl">🔒</span>
                </div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">No secrets found</h3>
                <p className="text-slate-500">Create your first secret to get started.</p>
            </div>
        );
    }

    const layoutClass = viewMode === 'grid'
        ? 'grid grid-cols-1 md:grid-cols-2 gap-4'
        : 'flex flex-col gap-2';

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
            </select>
            <div className="flex items-center gap-1">
                {toggleBtn('grid', LayoutGrid)}
                {toggleBtn('list', List)}
            </div>
        </div>
    );

    return (
        <div className="space-y-8">
            {toolbar}

            {sortedSecrets.length > 0 && (
                <div className={layoutClass}>
                    {sortedSecrets.map(secret => (
                        <SecretItem
                            key={secret.id}
                            secret={secret}
                            decryptedContent={decryptedSecrets[secret.id]}
                            onDecrypt={onDecrypt}
                            onLock={onLock}
                            onDelete={onDelete}
                            onShare={onShare}
                            onViewDetails={onViewDetails}
                            authType={authType}
                            viewMode={viewMode}
                        />
                    ))}
                </div>
            )}

            {sortedShared.length > 0 && (
                <div className="animate-in fade-in slide-in-from-bottom-4">
                    <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                        <span className="text-xl">📩</span> Shared with me
                    </h3>
                    <div className={layoutClass}>
                        {sortedShared.map(grant => (
                            <SecretItem
                                key={`shared_${grant.id}`}
                                secret={{
                                    ...grant.secret,
                                    id: grant.secret.id,
                                    isShared: true,
                                    encrypted_key: grant.encrypted_key
                                }}
                                decryptedContent={decryptedSecrets[`shared_${grant.id}`]}
                                onDecrypt={() => onDecrypt(grant, true)}
                                onLock={() => onLock(grant, true)}
                                onDelete={() => onRevoke(grant.id, true)}
                                onShare={() => { }}
                                authType={authType}
                                isSharedView={true}
                                viewMode={viewMode}
                            />
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default SecretList;
