import { useState, useEffect } from 'react';
import QRCode from 'qrcode';
import { X, Download, Smartphone, Loader2, Copy, ShieldAlert, ArrowLeft } from 'lucide-react';
import { usePQC } from '../../context/PQCContext';
import { useAuth } from '../../context/AuthContext';
import { generateTransferCode } from '../../utils/crypto';
import { uploadTransfer, packHandoff } from '../../services/transfer';
import { toast } from '../../utils/toast';

// Sender side of device-to-device key transfer. Two transports over the SAME
// client-side-encrypted vault blob:
//   • Encrypted backup file — user-chosen passphrase, downloaded .kvault file.
//   • Send to another device — auto passphrase, relayed via server, shown as a
//     QR (deep link) + one-time transfer code. Passphrase never hits the server.
export default function SendKeysModal({ onClose }) {
    const { exportEncryptedVault } = usePQC();
    const { token } = useAuth();

    const [mode, setMode] = useState('choose'); // 'choose' | 'file' | 'relay'
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    // File mode
    const [filePass, setFilePass] = useState('');
    const [filePass2, setFilePass2] = useState('');

    // Relay mode
    const [relay, setRelay] = useState(null); // { code, deepLink, qr, expiresAt }

    const handleExportFile = async (e) => {
        e.preventDefault();
        setError(null);
        if (filePass.length < 8) return setError("Use a passphrase of at least 8 characters.");
        if (filePass !== filePass2) return setError("Passphrases don't match.");
        setLoading(true);
        try {
            const blob = await exportEncryptedVault(filePass);
            const file = new Blob([blob], { type: 'application/json' });
            const url = URL.createObjectURL(file);
            const a = document.createElement('a');
            a.href = url;
            a.download = `kryptolog-keys-${Date.now()}.kvault`;
            a.click();
            URL.revokeObjectURL(url);
            toast.success("Encrypted backup downloaded.");
            onClose();
        } catch (err) {
            setError(err.message || "Export failed");
        } finally {
            setLoading(false);
        }
    };

    const startRelay = async () => {
        setError(null);
        setLoading(true);
        try {
            const passphrase = generateTransferCode();
            const blob = await exportEncryptedVault(passphrase);
            const { id, expires_at } = await uploadTransfer(blob, token);
            const code = packHandoff(id, passphrase);
            const deepLink = `${window.location.origin}/receive#t=${encodeURIComponent(code)}`;
            const qr = await QRCode.toDataURL(deepLink, { width: 240, margin: 1 });
            setRelay({ code, deepLink, qr, expiresAt: expires_at });
        } catch (err) {
            setError(err.message || "Could not start transfer");
            setMode('choose');
        } finally {
            setLoading(false);
        }
    };

    // Kick off the relay as soon as the user picks that mode.
    useEffect(() => {
        if (mode === 'relay' && !relay && !loading) startRelay();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [mode]);

    const copy = (text, label) => {
        navigator.clipboard.writeText(text);
        toast.success(`${label} copied`);
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-slate-850 w-full max-w-md rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col max-h-[85vh]">
                <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center">
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        {mode !== 'choose' && (
                            <button onClick={() => { setMode('choose'); setRelay(null); setError(null); }} className="p-1 -ml-1 hover:bg-slate-100 dark:hover:bg-slate-700 rounded">
                                <ArrowLeft className="w-4 h-4" />
                            </button>
                        )}
                        Transfer / Back up keys
                    </h2>
                    <button onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg">
                        <X className="w-5 h-5 text-slate-500" />
                    </button>
                </div>

                <div className="p-5 overflow-y-auto">
                    {error && (
                        <div className="mb-4 p-3 rounded-lg text-sm bg-red-500/10 border border-red-500/20 text-red-500">{error}</div>
                    )}

                    {mode === 'choose' && (
                        <div className="space-y-3">
                            <p className="text-sm text-slate-500 mb-2">
                                Your keys are encrypted before they leave this device. Keep the passphrase/code safe — it's the only thing that can unlock them.
                            </p>
                            <button
                                onClick={() => setMode('relay')}
                                className="w-full flex items-center gap-3 p-4 rounded-xl border border-slate-200 dark:border-slate-700 hover:border-emerald-500 transition-colors text-left"
                            >
                                <Smartphone className="w-6 h-6 text-emerald-500 shrink-0" />
                                <div>
                                    <div className="font-semibold text-slate-900 dark:text-white">Send to another device</div>
                                    <div className="text-xs text-slate-500">Scan a QR or type a one-time code on the other device.</div>
                                </div>
                            </button>
                            <button
                                onClick={() => setMode('file')}
                                className="w-full flex items-center gap-3 p-4 rounded-xl border border-slate-200 dark:border-slate-700 hover:border-indigo-500 transition-colors text-left"
                            >
                                <Download className="w-6 h-6 text-indigo-500 shrink-0" />
                                <div>
                                    <div className="font-semibold text-slate-900 dark:text-white">Encrypted backup file</div>
                                    <div className="text-xs text-slate-500">Download a passphrase-protected .kvault file.</div>
                                </div>
                            </button>
                        </div>
                    )}

                    {mode === 'file' && (
                        <form onSubmit={handleExportFile} className="space-y-4">
                            <p className="text-sm text-slate-500">
                                Choose a passphrase to encrypt the backup. You'll need it (and the file) to restore — store them separately.
                            </p>
                            <input
                                type="password" autoFocus value={filePass} onChange={e => setFilePass(e.target.value)}
                                placeholder="Backup passphrase (min 8 chars)"
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 dark:text-white outline-none focus:ring-2 focus:ring-indigo-500"
                            />
                            <input
                                type="password" value={filePass2} onChange={e => setFilePass2(e.target.value)}
                                placeholder="Confirm passphrase"
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 dark:text-white outline-none focus:ring-2 focus:ring-indigo-500"
                            />
                            <button type="submit" disabled={loading} className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-lg disabled:opacity-50 flex items-center justify-center gap-2">
                                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Download className="w-4 h-4" /> Download encrypted backup</>}
                            </button>
                        </form>
                    )}

                    {mode === 'relay' && (
                        <div className="space-y-4">
                            {loading || !relay ? (
                                <div className="flex flex-col items-center py-8 text-slate-500">
                                    <Loader2 className="w-6 h-6 animate-spin mb-2" />
                                    <span className="text-sm">Preparing secure transfer…</span>
                                </div>
                            ) : (
                                <>
                                    <p className="text-sm text-slate-500 text-center">
                                        On the other device, open <span className="font-mono">{window.location.host}/receive</span> and scan this, or enter the code.
                                    </p>
                                    <div className="flex justify-center">
                                        <img src={relay.qr} alt="Transfer QR code" className="rounded-lg border border-slate-200 dark:border-slate-700" />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-medium text-slate-500 mb-1">One-time transfer code</label>
                                        <div className="flex items-center gap-2">
                                            <code className="flex-1 break-all text-xs bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 dark:text-slate-200">{relay.code}</code>
                                            <button onClick={() => copy(relay.code, 'Code')} className="p-2 rounded-lg bg-slate-100 dark:bg-slate-750 hover:bg-slate-200 dark:hover:bg-slate-700" title="Copy code">
                                                <Copy className="w-4 h-4 text-slate-500" />
                                            </button>
                                        </div>
                                    </div>
                                    <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-400 text-xs">
                                        <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                                        <span>This code unlocks your keys — treat it like a password. It works once and expires in ~10 minutes.</span>
                                    </div>
                                </>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
