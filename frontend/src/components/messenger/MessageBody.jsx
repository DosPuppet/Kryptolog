import { useState } from 'react';
import { Lock, ShieldAlert } from 'lucide-react';

// The body of one chat bubble — shared by the DM and group views, which used
// to carry two copies of these three branches.
//
// An unauthenticated message is not shown until the reader asks (audit
// 2026-09-23 F-3). Signature verification gated ADOPTING a session key (H-1)
// but not DISPLAYING a message: anything that decrypted under a cached key was
// rendered in full, with a 10px "unverified" label beside the time. In a group,
// any member holds the session key, so a member and a colluding server could
// post text that rendered under someone else's name. Hidden by default when
// the signature failed, and when it is missing in a conversation where the
// author has signed before (the same `suspicious` the badge uses).
const isUnauthenticated = (msg, isMe, suspicious) =>
    !isMe && (msg.verified === false || (msg.verified == null && suspicious));

export default function MessageBody({ msg, isMe, suspicious, onDecrypt }) {
    const [revealed, setRevealed] = useState(false);

    if (msg.redacted) {
        // Not a failure: there is nothing to decrypt. A "Click to Decrypt"
        // button here could only ever spin and fail.
        return <p className="text-sm italic opacity-70">Content removed</p>;
    }

    if (msg.plainText) {
        if (isUnauthenticated(msg, isMe, suspicious) && !revealed) {
            return (
                <div className="text-sm">
                    <p className="flex items-center gap-1 font-semibold text-red-500">
                        <ShieldAlert className="w-4 h-4" /> Content hidden
                    </p>
                    <p className="text-xs opacity-80">
                        This message could not be proven to come from its sender. It may be forged.
                    </p>
                    <button
                        onClick={() => setRevealed(true)}
                        className="mt-1 text-xs underline opacity-80 hover:opacity-100"
                    >
                        Show it anyway
                    </button>
                </div>
            );
        }
        return <p className="text-sm">{msg.plainText}</p>;
    }

    return (
        <button
            onClick={() => onDecrypt(msg)}
            className={`flex items-center gap-2 text-sm font-semibold px-2 py-1 rounded bg-black/10 hover:bg-black/20 dark:bg-white/10 dark:hover:bg-white/20 transition-colors ${isMe ? 'text-white' : 'text-indigo-500 dark:text-indigo-400'}`}
        >
            <Lock className="w-4 h-4" /> Click to Decrypt
        </button>
    );
}
