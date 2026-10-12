import { useState } from 'react';
import { Loader2, Trash2 } from 'lucide-react';
import { useMessengerContext } from '../../context/MessengerContext';
import { toast } from '../../utils/toast';

// "Delete this conversation" (audit 2026-09-11 M-6). Two things a user can
// mean, and both are offered, because they are not the same promise:
//
//   • hide it — always: it leaves this user's list on every device, and the
//     other side keeps their copy, which is theirs;
//   • erase my messages in it — optional: the user's own messages are removed
//     for everyone, under a signature the extension asks about (or the vault
//     password), and the other side's messages stay.
//
// The wording says exactly that, because "deleted" that quietly means "hidden
// from you" is the kind of promise a deletion feature must not make.
export default function DeleteConversationDialog({ kind, conversation, label, onClose }) {
    const { deleteConversation } = useMessengerContext();
    const [eraseMine, setEraseMine] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState('');

    const confirm = async () => {
        setBusy(true);
        setError('');
        try {
            const erased = await deleteConversation(kind, conversation, { eraseMine });
            if (erased) {
                const removed = (erased.redacted || 0) + (erased.deleted || 0);
                toast.success(`Removed ${removed} of your message(s) and hid the conversation.`);
                if (erased.kept) toast.info(`${erased.kept} message(s) could not be removed.`);
            } else {
                toast.success('Conversation hidden.');
            }
            onClose();
        } catch (e) {
            // An erase commits round by round, so a failure part-way has still
            // removed what it removed; the message from the erase says so.
            setError(e.message || 'Could not delete the conversation.');
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
            <div className="w-full max-w-md rounded-xl bg-white dark:bg-slate-800 p-5 shadow-xl">
                <h3 className="flex items-center gap-2 text-lg font-bold text-slate-900 dark:text-white">
                    <Trash2 className="w-5 h-5 text-red-500" /> Delete conversation with {label}?
                </h3>
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                    It disappears from your list on all your devices. The other side keeps
                    their copy — it comes back here if a new message arrives.
                </p>
                <label className="mt-4 flex items-start gap-2 text-sm text-slate-700 dark:text-slate-200">
                    <input
                        type="checkbox"
                        className="mt-1"
                        checked={eraseMine}
                        onChange={(e) => setEraseMine(e.target.checked)}
                    />
                    <span>
                        Also erase <strong>my</strong> messages in it, for everyone. Theirs stay.
                        This cannot be undone, and you will be asked to confirm with your key.
                    </span>
                </label>
                {error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
                <div className="mt-5 flex justify-end gap-2">
                    <button onClick={onClose} disabled={busy} className="px-3 py-1.5 rounded text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700">
                        Cancel
                    </button>
                    <button onClick={confirm} disabled={busy} className="flex items-center gap-1 px-3 py-1.5 rounded text-sm font-semibold text-white bg-red-600 hover:bg-red-500 disabled:opacity-60">
                        {busy && <Loader2 className="w-4 h-4 animate-spin" />}
                        {eraseMine ? 'Erase my messages and delete' : 'Delete'}
                    </button>
                </div>
            </div>
        </div>
    );
}
