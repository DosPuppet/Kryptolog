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


// --- Accessors ---
//
// These three questions were asked inline throughout handlers/: is the vault
// unlocked (15 times), which account is active (11), and may this origin use it
// (7). Each phrasing was identical, which is how one of them ends up edited
// alone. Their error strings are asserted by the tests, so they are part of the
// contract, not incidental text.

/** Throw unless the vault is unlocked. */
export const requireUnlocked = () => {
    if (state.isLocked) throw new Error("Locked");
};

/** The active account, or null. Assumes the vault is already unlocked. */
export const activeAccount = () =>
    state.vault.accounts.find(a => a.id === state.vault.activeAccountId) || null;

/**
 * The active account, or throw.
 *
 * The non-throwing form exists for the approval callbacks: they run after the
 * request has been handed to the user, so the dispatcher's try/catch is no
 * longer above them and they must answer sendResponse themselves.
 */
export const requireActiveAccount = () => {
    const account = activeAccount();
    if (!account) throw new Error("No active account");
    return account;
};

/**
 * Throw unless `origin` is a site the user has connected.
 *
 * `origin` must be Chrome's authoritative sender.origin (audit M4), never a
 * value the caller supplied — a page that names its own origin authorizes
 * itself. A null origin fails, rather than being treated as "no restriction".
 */
export const requireConnectedOrigin = (origin) => {
    if (!origin || !state.vault.permissions[origin]) {
        throw new Error("Site not connected");
    }
    return origin;
};
