import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Smartphone, FileJson, Loader2, ArrowLeft, Upload } from 'lucide-react';
import { usePQC } from '../../context/PQCContext';
import { claimTransfer, unpackHandoff } from '../../services/transfer';
import { toast } from '../../utils/toast';

// Receiver side of device-to-device key transfer (target device, not signed in).
// Tab 1: one-time code / QR (relay). Tab 2: encrypted backup file.
// Both end by decrypting the blob and creating a local vault under a NEW device
// password, then logging in with the transferred identity.
export default function ReceiveKeys() {
    const { receiveVault } = usePQC();
    const navigate = useNavigate();

    const [tab, setTab] = useState('code'); // 'code' | 'file'
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    const [code, setCode] = useState('');
    const [fileBlob, setFileBlob] = useState(null);
    const [fileName, setFileName] = useState('');
    const [filePass, setFilePass] = useState('');
    const [newPass, setNewPass] = useState('');

    // Prefill the code from a scanned deep link (#t=<code>) and clear the hash so
    // the secret doesn't linger in the address bar / history.
    useEffect(() => {
        const hash = window.location.hash || '';
        const m = hash.match(/[#&]t=([^&]+)/);
        if (m) {
            try { setCode(decodeURIComponent(m[1])); } catch { setCode(m[1]); }
            history.replaceState(null, '', window.location.pathname);
        }
    }, []);

    const finish = (account) => {
        toast.success(`Welcome back, ${account?.username || 'you'} — keys imported.`);
        // Auth state flips to authenticated; the router takes us to the app.
        navigate('/secrets', { replace: true });
    };

    const handleCode = async (e) => {
        e.preventDefault();
        setError(null);
        const parsed = unpackHandoff(code);
        if (!parsed) return setError("That doesn't look like a valid transfer code.");
        if (newPass.length < 6) return setError("Choose a device password of at least 6 characters.");
        setLoading(true);
        try {
            const blob = await claimTransfer(parsed.id);
            const account = await receiveVault(blob, parsed.passphrase, newPass);
            finish(account);
        } catch (err) {
            setError(err.message || "Transfer failed");
        } finally {
            setLoading(false);
        }
    };

    const handleFilePick = (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        setError(null);
        setFileName(file.name);
        const reader = new FileReader();
        reader.onload = (ev) => setFileBlob(ev.target.result);
        reader.onerror = () => setError("Could not read the selected file.");
        reader.readAsText(file);
    };

    const handleFile = async (e) => {
        e.preventDefault();
        setError(null);
        if (!fileBlob) return setError("Choose a .kvault backup file first.");
        if (!filePass) return setError("Enter the backup passphrase.");
        if (newPass.length < 6) return setError("Choose a device password of at least 6 characters.");
        setLoading(true);
        try {
            const account = await receiveVault(fileBlob, filePass, newPass);
            finish(account);
        } catch (err) {
            setError(err.message || "Import failed");
        } finally {
            setLoading(false);
        }
    };

    const tabBtn = (id, label, Icon) => (
        <button
            onClick={() => { setTab(id); setError(null); }}
            className={`flex-1 flex items-center justify-center gap-2 py-2 text-sm font-medium rounded-lg transition-colors ${tab === id ? 'bg-emerald-600 text-white' : 'bg-slate-100 dark:bg-slate-750 text-slate-500'}`}
        >
            <Icon className="w-4 h-4" /> {label}
        </button>
    );

    const newPassField = (
        <div>
            <label className="block text-xs font-medium text-slate-500 mb-1">New password for this device</label>
            <input
                type="password" value={newPass} onChange={e => setNewPass(e.target.value)}
                placeholder="Protects the vault on this device"
                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 dark:text-white outline-none focus:ring-2 focus:ring-emerald-500"
            />
        </div>
    );

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center p-4">
            <div className="max-w-md w-full bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-2xl p-8 shadow-2xl">
                <button onClick={() => navigate('/', { replace: true })} className="flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to sign in
                </button>

                <div className="flex flex-col items-center text-center mb-6">
                    <div className="w-14 h-14 bg-emerald-500/10 rounded-full flex items-center justify-center mb-3">
                        <Shield className="w-7 h-7 text-emerald-500" />
                    </div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Receive your keys</h1>
                    <p className="text-sm text-slate-500 mt-1">Import an identity from another device.</p>
                </div>

                <div className="flex gap-2 mb-5">
                    {tabBtn('code', 'Transfer code', Smartphone)}
                    {tabBtn('file', 'Backup file', FileJson)}
                </div>

                {error && (
                    <div className="mb-4 p-3 rounded-lg text-sm bg-red-500/10 border border-red-500/20 text-red-500 text-center">{error}</div>
                )}

                {tab === 'code' ? (
                    <form onSubmit={handleCode} className="space-y-4">
                        <div>
                            <label className="block text-xs font-medium text-slate-500 mb-1">One-time transfer code</label>
                            <textarea
                                value={code} onChange={e => setCode(e.target.value)} rows={2}
                                placeholder="Paste the code from the other device (or scan its QR)"
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-xs font-mono dark:text-white outline-none focus:ring-2 focus:ring-emerald-500"
                            />
                        </div>
                        {newPassField}
                        <button type="submit" disabled={loading} className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 rounded-lg disabled:opacity-50 flex items-center justify-center gap-2">
                            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Import keys'}
                        </button>
                    </form>
                ) : (
                    <form onSubmit={handleFile} className="space-y-4">
                        <label className="w-full flex items-center gap-2 cursor-pointer bg-slate-50 dark:bg-slate-900 border border-dashed border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-600 dark:text-slate-300 hover:border-emerald-500 transition-colors">
                            <Upload className="w-4 h-4 text-emerald-500 shrink-0" />
                            <span className="truncate">{fileName || 'Choose a .kvault file…'}</span>
                            <input type="file" accept=".kvault,application/json,.json" className="hidden" onChange={handleFilePick} />
                        </label>
                        <input
                            type="password" value={filePass} onChange={e => setFilePass(e.target.value)}
                            placeholder="Backup passphrase"
                            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 dark:text-white outline-none focus:ring-2 focus:ring-emerald-500"
                        />
                        {newPassField}
                        <button type="submit" disabled={loading} className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 rounded-lg disabled:opacity-50 flex items-center justify-center gap-2">
                            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Import keys'}
                        </button>
                    </form>
                )}
            </div>
        </div>
    );
}
