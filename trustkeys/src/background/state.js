// State Management
export const state = {
    isLocked: true,
    hasPassword: false,
    vault: null,
    sessionPassword: null,
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
