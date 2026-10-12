import { useEffect, useState } from 'react';
import { ShieldAlert, Fingerprint } from 'lucide-react';
import { checkContactKey, trustContactKey } from '../../services/trustedKeys';
import { safetyNumber } from '../../utils/fingerprint';
import { displayName } from '../../utils/format';

// A contact's key, as the messenger shows it (audit 2026-10-12 K-05).
//
// The TOFU store already knew when a contact's encryption key changed, but only
// the share dialog asked it: a key swapped by the directory went unnoticed in
// every conversation, and no conversation showed a safety number to check one
// against. Here, in every conversation:
//   • the safety number is one click away, to compare out of band;
//   • a CHANGED key raises a banner, and nothing is sent to that contact until
//     the reader confirms it (MessengerContext refuses the send, so this is
//     not a UI-only gate).
export default function KeyTrustPanel({ user, compact = false, onTrusted }) {
    const address = user?.address;
    const key = user?.encryption_public_key;
    const [state, setState] = useState(() => checkContactKey(address, key));
    const [number, setNumber] = useState(null);
    const [open, setOpen] = useState(false);

    useEffect(() => { setState(checkContactKey(address, key)); }, [address, key]);
    useEffect(() => {
        let live = true;
        if ((open || state === 'changed') && address && key) {
            safetyNumber(address, key).then((n) => { if (live) setNumber(n); });
        }
        return () => { live = false; };
    }, [open, state, address, key]);

    if (!address || !key) return null;

    const accept = () => {
        trustContactKey(address, key);
        setState('unchanged');
        onTrusted?.();
    };

    if (state === 'changed') {
        const when = user.key_changed_at ? ` on ${new Date(user.key_changed_at).toLocaleDateString()}` : '';
        return (
            <div className="m-2 p-3 rounded-lg border border-red-300 bg-red-50 dark:bg-red-950/40 dark:border-red-800 text-sm">
                <p className="flex items-center gap-1 font-semibold text-red-600 dark:text-red-400">
                    <ShieldAlert className="w-4 h-4" /> {displayName(user)}&apos;s encryption key changed{when}
                </p>
                <p className="mt-1 text-red-700 dark:text-red-300">
                    Nothing will be sent to them until you confirm. Compare this safety number with them
                    in person or by phone — a different number means someone else is holding the key.
                </p>
                <p className="mt-2 font-mono text-xs tracking-wider">{number ?? '…'}</p>
                <button onClick={accept} className="mt-2 px-3 py-1 rounded bg-red-600 text-white text-xs font-semibold hover:bg-red-500">
                    I verified it — trust the new key
                </button>
            </div>
        );
    }

    return (
        <div className={compact ? 'text-xs' : 'px-3 py-1 text-xs border-b border-slate-200 dark:border-slate-700'}>
            <button onClick={() => setOpen((o) => !o)} className="flex items-center gap-1 text-slate-500 hover:text-indigo-500">
                <Fingerprint className="w-3 h-3" /> {open ? 'Hide' : 'Show'} safety number
            </button>
            {open && <p className="mt-1 font-mono tracking-wider text-slate-600 dark:text-slate-300">{number ?? '…'}</p>}
        </div>
    );
}
