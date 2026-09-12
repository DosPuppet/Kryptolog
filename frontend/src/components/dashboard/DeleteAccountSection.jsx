import { useState } from 'react';
import { Trash2, Loader2, AlertTriangle } from 'lucide-react';
import { usePQC } from '../../context/PQCContext';
import confirmDialog from '../../utils/confirm';
import { toast } from '../../utils/toast';

// The two modes, and what each one actually costs. Spelled out here rather than
// summarised, because every line is something the user cannot find out
// afterwards: one of them is reversible and one of them is not, and both give
// away things people usually assume "delete my account" keeps or removes.
const MODES = [
    {
        id: 'leave',
        title: 'Leave — keep the data',
        summary: 'Your account disappears. Everything you have written stays where it is.',
        keeps: [
            'Secrets, files, documents and workflows stay on the server, attached to your key.',
            'Your messages stay readable to the people you sent them to.',
            'You can come back: logging in with this same vault restores the account and its data.',
        ],
        costs: [
            'You disappear from the directory and show as "User removed" to everyone.',
            'You are removed from every group, and have to be re-added to return.',
            'You will choose a new username, and an invite code if the server needs one.',
        ],
    },
    {
        id: 'erase',
        title: 'Erase — delete the history',
        summary: 'Your content is removed as far as it can be without destroying other people\'s.',
        keeps: [
            'Signatures you gave on other people\'s workflows stay — they are that owner\'s evidence.',
            'Documents you already released through a completed workflow stay with their recipients.',
            'Messages other people sent you stay: they are their words, not yours.',
        ],
        costs: [
            'THIS KEY CAN NEVER BE USED AGAIN. To register later you need a new key, added from Manage Vault.',
            'Secrets, files and pending workflows are deleted.',
            'Your message text is removed, but your address stays on messages others still read.',
            'A group where you are the last member is deleted, with everything in it.',
        ],
    },
];

/**
 * The danger zone: deleting the server-side account.
 *
 * Deliberately two steps before anything irreversible happens — a mode choice
 * that has to be read, then a confirmation naming the chosen mode. Note that
 * ConfirmDialogHost maps Enter to "confirm", so chained dialogs alone would be
 * clearable by holding a key down; the signing prompt that follows is what
 * makes the sequence a decision rather than a reflex.
 */
const DeleteAccountSection = () => {
    const { deleteServerAccount } = usePQC();
    const [choosing, setChoosing] = useState(false);
    const [mode, setMode] = useState('leave');
    // Erasing blocks the key forever, so keeping it on the device is almost
    // never what the user wants — but it destroys the keys, so it is opt-out
    // rather than automatic. Never offered for `leave`: the vault is precisely
    // what makes leaving reversible.
    const [alsoForget, setAlsoForget] = useState(true);
    const [busy, setBusy] = useState(false);

    const chosen = MODES.find((m) => m.id === mode);

    const handleDelete = async () => {
        const ok = await confirmDialog({
            title: mode === 'erase' ? 'Erase this account?' : 'Leave and keep the data?',
            message:
                mode === 'erase'
                    ? 'This cannot be undone, and this key can never register again. You will be asked to sign the deletion.'
                    : 'Your account will be removed from the directory. You can restore it later by logging in with this same vault.',
            confirmText: mode === 'erase' ? 'Erase everything' : 'Leave',
            danger: true,
        });
        if (!ok) return;

        setBusy(true);
        try {
            await deleteServerAccount(mode, { forgetVault: mode === 'erase' && alsoForget });
            // Nothing to navigate to: the provider logs out, and App swaps the
            // route table back to the login screen on its own.
            toast.success(mode === 'erase' ? 'Account erased.' : 'Account removed.');
        } catch (e) {
            console.error('Account deletion failed', e);
            toast.error(e.message || 'Could not delete the account.');
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="border-t border-slate-100 dark:border-slate-700 pt-4">
            <h4 className="text-sm font-bold text-red-600 dark:text-red-400 flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4" /> Danger zone
            </h4>

            {!choosing ? (
                <button
                    type="button"
                    onClick={() => setChoosing(true)}
                    className="w-full bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg font-medium shadow-lg shadow-red-500/20 flex items-center justify-center gap-2"
                >
                    <Trash2 className="w-4 h-4" /> Delete user
                </button>
            ) : (
                <div className="space-y-3">
                    <div className="space-y-2">
                        {MODES.map((m) => (
                            <label
                                key={m.id}
                                className={`block cursor-pointer rounded-lg border p-3 transition-colors ${mode === m.id
                                    ? 'border-red-400 bg-red-50 dark:bg-red-900/20'
                                    : 'border-slate-200 dark:border-slate-700 hover:border-red-300'
                                    }`}
                            >
                                <div className="flex items-start gap-2">
                                    <input
                                        type="radio"
                                        name="delete-mode"
                                        value={m.id}
                                        checked={mode === m.id}
                                        onChange={() => setMode(m.id)}
                                        className="mt-1"
                                    />
                                    <div>
                                        <div className="text-sm font-semibold text-slate-900 dark:text-white">{m.title}</div>
                                        <div className="text-xs text-slate-500 dark:text-slate-400">{m.summary}</div>
                                    </div>
                                </div>
                            </label>
                        ))}
                    </div>

                    <div className="rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 p-3 space-y-2">
                        <div>
                            <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">What stays</div>
                            <ul className="mt-1 space-y-1">
                                {chosen.keeps.map((line) => (
                                    <li key={line} className="text-xs text-slate-600 dark:text-slate-400">• {line}</li>
                                ))}
                            </ul>
                        </div>
                        <div>
                            <div className="text-[11px] font-semibold uppercase tracking-wide text-red-600 dark:text-red-400">What you lose</div>
                            <ul className="mt-1 space-y-1">
                                {chosen.costs.map((line) => (
                                    <li key={line} className="text-xs text-slate-600 dark:text-slate-400">• {line}</li>
                                ))}
                            </ul>
                        </div>
                        <p className="text-[11px] text-slate-400 pt-1">
                            Your vault stays on this device either way — the keys are yours.
                            Other members&apos; messages carry session keys wrapped to your address
                            inside their own signed payloads, and those cannot be removed without
                            breaking their signatures.
                        </p>
                    </div>

                    {mode === 'erase' && (
                        <label className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-400">
                            <input
                                type="checkbox"
                                checked={alsoForget}
                                onChange={(e) => setAlsoForget(e.target.checked)}
                                className="mt-0.5"
                            />
                            <span>
                                Also remove this identity from this device&apos;s vault. Recommended:
                                the key is blocked forever, and while it is stored here the login
                                screen can only offer to unlock it. Other identities in the vault are
                                untouched. <strong>This destroys this identity&apos;s keys</strong> —
                                keep a backup first if they still matter.
                            </span>
                        </label>
                    )}

                    <div className="flex gap-2">
                        <button
                            type="button"
                            onClick={() => setChoosing(false)}
                            disabled={busy}
                            className="flex-1 px-4 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                        >
                            Cancel
                        </button>
                        <button
                            type="button"
                            onClick={handleDelete}
                            disabled={busy}
                            className="flex-1 bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg font-medium shadow-lg shadow-red-500/20 disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Trash2 className="w-4 h-4" /> Continue</>}
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DeleteAccountSection;
