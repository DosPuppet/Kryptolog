import { useRef } from 'react';
import API_ENDPOINTS from '../../config';
import { apiFetch } from '../../services/api';

// Names for DM partners the sidebar has never seen.
//
// The NEW_MESSAGE frame is built by hand in backend/routers/messenger.py and
// carries addresses only — no username — so the first message of a conversation
// arrived nameless and stayed that way until the next `GET /messages/conversations`,
// i.e. until a reload. Both ends saw it: the server echoes the frame back to the
// sender for device sync, and that echo can land before the POST resolves.
//
// A username is public directory data, NOT part of the ciphertext, so it can be
// resolved the moment the frame lands — the label does not have to wait for the
// body to be decrypted, and it is the only thing on screen that says who the
// message is from.
//
// Cached per address: one lookup per partner per session. A conversation cannot
// change who it is with, and in-flight requests are shared so a burst of
// messages from one unknown sender makes a single request rather than one each.
export const usePartnerDirectory = ({ token }) => {
    const cache = useRef({});
    const inFlight = useRef({});

    /** The directory record for `address`, or null if it can't be fetched. */
    const resolvePartner = (address) => {
        const addr = String(address || '').toLowerCase();
        if (!addr) return Promise.resolve(null);
        if (cache.current[addr]) return Promise.resolve(cache.current[addr]);
        if (inFlight.current[addr]) return inFlight.current[addr];

        const pending = apiFetch(API_ENDPOINTS.USERS.GET(addr), token)
            .then((partner) => {
                if (partner?.address) cache.current[addr] = partner;
                return partner ?? null;
            })
            // Best-effort. A failed lookup leaves the short address on screen,
            // which is a truthful label — and the failure is NOT cached, so the
            // next message from the same partner tries again.
            .catch(() => null)
            .finally(() => { delete inFlight.current[addr]; });

        inFlight.current[addr] = pending;
        return pending;
    };

    return { resolvePartner };
};
