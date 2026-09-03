// Pending-approval lifecycle (audit M-6).
//
// Every external SIGN / DECRYPT / UNWRAP used to add an entry to
// state.pendingRequests and open an OS window, with no cap, no timeout, no
// dedup and no cleanup. Three consequences, all reachable from any connected
// page: a looping site opened a window per call; closing a window without
// clicking left the page's promise pending forever AND the Map entry
// permanently; and nothing bounded how many entries accumulated.
//
// Four rules, each closing one of those:
//   • one window at a time — a second request focuses it and queues behind it;
//   • a per-origin cap, so one site cannot fill the queue;
//   • a timeout, so an unanswered request always settles;
//   • dismissing the window rejects everything it was asking about.
//
// Every request registered here settles EXACTLY once, whichever path gets there
// first — that is what stops a page promise hanging forever.

import { state } from './state.js';

export const MAX_PENDING_PER_ORIGIN = 3;
// A global ceiling as well: the per-origin cap alone still lets N connected
// sites contribute N*3 entries.
export const MAX_PENDING_TOTAL = 10;
// Long enough for a user to read and click, short enough that an ignored
// request does not sit forever. Note MV3 may terminate the worker first, which
// drops the Map and closes the message channel — the page sees lastError and
// rejects — so this is the backstop for a worker that stays alive.
export const APPROVAL_TIMEOUT_MS = 3 * 60 * 1000;

const pendingForOrigin = (origin) => {
    let n = 0;
    for (const req of state.pendingRequests.values()) if (req.origin === origin) n++;
    return n;
};

/** Open the approval window, or focus the one already open. */
const openOrFocusWindow = async (route, params) => {
    if (state.approvalWindowId !== null) {
        try {
            await chrome.windows.update(state.approvalWindowId, { focused: true });
            return true;
        } catch {
            // Window is gone and we never saw onRemoved (e.g. worker restarted).
            state.approvalWindowId = null;
        }
    }

    const queryString = new URLSearchParams({ route, ...params }).toString();
    const width = 360;
    const height = 600;
    let left, top;
    try {
        const lastWin = await chrome.windows.getLastFocused();
        if (lastWin && lastWin.left !== undefined && lastWin.width !== undefined) {
            left = lastWin.left + lastWin.width - width - 20;
            top = lastWin.top + 80;
        }
    } catch (e) {
        console.warn("Failed to calculate popup position", e);
    }

    try {
        const win = await chrome.windows.create({
            url: `index.html?${queryString}`,
            type: 'popup', width, height, left, top, focused: true,
        });
        state.approvalWindowId = win?.id ?? null;
        return true;
    } catch (e) {
        console.warn("Failed to open approval window", e);
        return false;
    }
};

/**
 * Register an approval request and surface it to the user.
 *
 * Always settles: onApprove on approval, onReject on rejection, timeout,
 * dismissal, cap refusal, or failure to open the window. Callers therefore never
 * need a fallback path — that absence is what left promises hanging.
 */
export const requestApproval = async ({ type, origin, data, route, onApprove, onReject }) => {
    if (state.pendingRequests.size >= MAX_PENDING_TOTAL) {
        onReject("Too many approval requests are already waiting");
        return null;
    }
    if (pendingForOrigin(origin) >= MAX_PENDING_PER_ORIGIN) {
        onReject(`Too many pending approvals for ${origin}`);
        return null;
    }

    // Unguessable id (audit M-5). Math.random().toString(36) gave ~9 chars of
    // non-cryptographic randomness for the key that identifies an approvable
    // signing/decryption request — the internal-sender guard on
    // GET_PENDING_REQUEST / RESOLVE_REQUEST is the real defense, but the id
    // should not be the weak half of it.
    const id = crypto.randomUUID();

    let settled = false;
    const finish = () => {
        if (settled) return false;
        settled = true;
        clearTimeout(timer);
        state.pendingRequests.delete(id);
        return true;
    };

    const timer = setTimeout(() => {
        if (finish()) onReject("Approval timed out");
    }, APPROVAL_TIMEOUT_MS);

    state.pendingRequests.set(id, {
        type,
        origin,
        data,
        resolve: () => { if (finish()) onApprove(); },
        reject: (err) => { if (finish()) onReject(err || "Rejected"); },
    });

    if (!await openOrFocusWindow(route, { requestId: id })) {
        const req = state.pendingRequests.get(id);
        if (req) req.reject("Could not open the approval window");
        return null;
    }
    return id;
};

/** The oldest pending request id, or null. Drives the popup's queue. */
export const nextApprovalId = () => {
    for (const id of state.pendingRequests.keys()) return id;
    return null;
};

export const peekApproval = (requestId) => {
    const id = requestId || nextApprovalId();
    if (!id) return null;
    const req = state.pendingRequests.get(id);
    return req ? { id, type: req.type, data: req.data } : null;
};

/** Approve or reject one request. Returns the next queued id, if any. */
export const settleApproval = (requestId, approved) => {
    const req = state.pendingRequests.get(requestId);
    if (!req) return { ok: false, next: nextApprovalId() };
    if (approved) req.resolve(); else req.reject();
    return { ok: true, next: nextApprovalId() };
};

export const rejectAllApprovals = (reason) => {
    // Snapshot first: reject() mutates the Map as it settles each entry.
    for (const req of [...state.pendingRequests.values()]) req.reject(reason);
    state.pendingRequests.clear();
};

/**
 * The approval window was dismissed. Closing it without clicking is a refusal,
 * so every request it was asking about is rejected — previously those promises
 * simply never settled and their Map entries never went away.
 */
export const handleWindowClosed = (windowId) => {
    if (windowId === state.popupWindowId) state.popupWindowId = null;
    if (windowId !== state.approvalWindowId) return;
    state.approvalWindowId = null;
    rejectAllApprovals("Approval window closed");
};
