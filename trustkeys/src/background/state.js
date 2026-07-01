// State Management
export const state = {
    isLocked: true,
    hasPassword: false,
    vault: null,
    sessionPassword: null,
    // Cached vault-encryption key for the unlocked session. The PBKDF2 KDF is
    // deliberately slow (600k iters); we derive it once at unlock and reuse it
    // for every save instead of re-stretching the password each time.
    derivedKey: null,   // CryptoKey from deriveKey(sessionPassword, vaultSalt)
    vaultSalt: null,    // Uint8Array salt the derivedKey was derived with
    pendingRequests: new Map() // ID -> { resolve, reject, type, data }
};

export const setState = (newState) => {
    Object.assign(state, newState);
};

export const setSessionPassword = (pwd) => {
    state.sessionPassword = pwd;
};

export const getSessionPassword = () => {
    return state.sessionPassword;
};
