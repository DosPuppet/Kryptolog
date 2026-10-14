import { useMemo, useState } from 'react';
import { KeyRound, RefreshCw, Trash2, Loader2 } from 'lucide-react';
import { usePQC } from '../../context/PQCContext';
import { encryptionKeyId } from '../../utils/crypto';
import confirmDialog from '../../utils/confirm';
import { toast } from '../../utils/toast';

const shortKid = (kid) => `${kid.slice(0, 8)}…${kid.slice(-4)}`;

// Replacing the encryption key (crypto-core 5.1.0), and the keys it retired.
//
// What the dialogs say is what the user cannot find out afterwards: contacts
// will be stopped until they check the new safety number (the rotation is
// signed by the identity key, so it cannot vouch for itself — K-05), the old
// history stays readable on this device through the retired key, and
// destroying that key ends that, everywhere, for good.
const EncryptionKeySection = () => {
    const { ownEncryptionKey, rotateEncryptionKey, destroyRetiredEncryptionKey, listRetiredEncryptionKeys } = usePQC();
    const [busy, setBusy] = useState(false);
    const [, refresh] = useState(0);
    const kid = useMemo(() => (ownEncryptionKey ? encryptionKeyId(ownEncryptionKey) : null), [ownEncryptionKey]);
    const retired = listRetiredEncryptionKeys();

    const rotate = async () => {
        const ok = await confirmDialog({
            title: 'Replace your encryption key?',
            message:
                'A new encryption key is created on this device and published. Everything you hold is moved to it. ' +
                'Your contacts will see that your key changed and must check your new safety number before they ' +
                'can write to you again. Your message history stays readable here with the old key, which is kept ' +
                'until you destroy it.',
            confirmText: 'Replace the key',
        });
        if (!ok) return;
        setBusy(true);
        try {
            const { rewrapped, unreadable } = await rotateEncryptionKey();
            toast.success(
                `Encryption key replaced. ${rewrapped} key(s) moved to it` +
                (unreadable ? `; ${unreadable} could not be opened on this device.` : '.')
            );
        } catch (e) {
            toast.error(e.message || 'Could not replace the encryption key.');
        } finally {
            setBusy(false);
            refresh((n) => n + 1);
        }
    };

    const destroy = async (retiredKid) => {
        const ok = await confirmDialog({
            title: 'Destroy this key?',
            message:
                'Anything still sealed to this key — older message history above all — becomes unreadable on ' +
                'this device, for good. Destroy it if you think it was compromised.',
            confirmText: 'Destroy the key',
            danger: true,
        });
        if (!ok) return;
        try {
            await destroyRetiredEncryptionKey(retiredKid);
            toast.success('Key destroyed.');
        } catch (e) {
            toast.error(e.message || 'Could not destroy the key.');
        } finally {
            refresh((n) => n + 1);
        }
    };

    return (
        <div className="border-t border-slate-100 dark:border-slate-700 pt-4 space-y-3" data-testid="encryption-key-section">
            <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <KeyRound className="w-4 h-4" /> Encryption key
            </h4>
            {kid && (
                <p className="text-xs text-slate-500 dark:text-slate-400">
                    Current key <span className="font-mono" data-testid="current-kid">{shortKid(kid)}</span>
                </p>
            )}
            <button
                type="button"
                onClick={rotate}
                disabled={busy || !ownEncryptionKey}
                className="w-full px-4 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50 flex items-center justify-center gap-2"
            >
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                Replace my encryption key
            </button>
            {retired.length > 0 && (
                <div className="space-y-1">
                    <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Retired keys, kept to read older history</p>
                    {retired.map((key) => (
                        <div key={key.kid} className="flex items-center justify-between text-xs" data-testid="retired-key">
                            <span className="font-mono text-slate-600 dark:text-slate-300">
                                {shortKid(key.kid)}
                                {key.retiredAt ? ` · retired ${new Date(key.retiredAt).toLocaleDateString()}` : ''}
                            </span>
                            <button
                                type="button"
                                onClick={() => destroy(key.kid)}
                                className="text-red-600 hover:text-red-500 flex items-center gap-1"
                            >
                                <Trash2 className="w-3.5 h-3.5" /> Destroy
                            </button>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default EncryptionKeySection;
