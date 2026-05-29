

// Helper for postMessage
window.postMessagePromise = (data) => {
    return new Promise((resolve, reject) => {
        const id = Math.random().toString(36).substr(2, 9);
        const listener = (event) => {
            // Check source precisely
            if (event.source !== window) return;

            if (event.data.id === id && event.data.source === 'TRUSTKEYS_CONTENT') {
                window.removeEventListener('message', listener);
                if (event.data.success) resolve(event.data.result);
                else reject(new Error(event.data.error));
            }
        };
        window.addEventListener('message', listener);
        window.postMessage({ ...data, id, source: 'TRUSTKEYS_PAGE' }, '*');
    });
};

window.trustkeys = {
    version: "1.0.0",
    getAccount: async () => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_GET_ACCOUNT' });
    },
    sign: async (message) => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_SIGN', message });
    },
    verify: async (message, signature, publicKey) => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_VERIFY', message, signature, publicKey });
    },
    encrypt: async (message, publicKey) => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_ENCRYPT', message, publicKey });
    },
    decrypt: async (ciphertext) => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_DECRYPT', data: ciphertext });
    },
    connect: async () => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_CONNECT' });
    },
    isConnected: async () => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_CHECK_CONNECTION' });
    },
    handshake: async () => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_HANDSHAKE' });
    },
    generateSessionKey: async () => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_GENERATE_SESSION_KEY' });
    },
    wrapSessionKey: async (sessionKey, publicKey) => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_WRAP_SESSION_KEY', sessionKey, publicKey });
    },
    unwrapSessionKey: async (wrappedKey) => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_UNWRAP_SESSION_KEY', wrappedKey });
    },
    unwrapManySessionKeys: async (wrappedKeys) => {
        return window.postMessagePromise({ type: 'TRUSTKEYS_UNWRAP_MANY_SESSION_KEYS', wrappedKeys });
    }
};

// Freeze to prevent modification
Object.freeze(window.trustkeys);

