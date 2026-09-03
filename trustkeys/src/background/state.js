// State Management
export const state = {
    isLocked: true,
    hasPassword: false,
    vault: null,

    // The unlocked vault's encryption key (audit M-4). The PASSWORD is
    // deliberately NOT here and not in chrome.storage.session: it is the PBKDF2
    // input, it outlives any salt change, and it is what a user is likely to
    // have reused elsewhere. These two are equivalent for opening this vault and
    // useless for anything else. See background/session.js.
    //
    // The PBKDF2 KDF is deliberately slow (600k iters), so it runs once at
    // unlock and every subsequent save reuses the cached key.
    vaultKey: null,       // non-extractable CryptoKey, for encrypt/decrypt
    vaultKeyBytes: null,  // the same key raw, so it survives a worker restart
    vaultSalt: null,      // Uint8Array salt vaultData was written with

    pendingRequests: new Map(), // ID -> { type, origin, data, resolve, reject }

    // Background-opened windows, tracked so a looping site focuses an existing
    // one instead of stacking an OS window per call (audit M-6).
    //
    // Two trackers, not one: the "please unlock" nudge stays open showing the
    // dashboard after the user unlocks, and if it shared a slot with the
    // approval window then a later signature request would focus THAT window —
    // which is showing the dashboard, not the request — and the request would
    // sit unanswered until it timed out.
    popupWindowId: null,    // the unlock nudge
    approvalWindowId: null, // the window that shows pending approvals
};

export const setState = (newState) => {
    Object.assign(state, newState);
};
