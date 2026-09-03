// Page-facing API, injected into the MAIN world.
//
// Everything lives inside an IIFE so the request helper is a closure variable
// (audit L-11). It used to be `window.postMessagePromise`, a global that every
// frozen method on window.trustkeys then called — so freezing the API object
// protected nothing: the page could replace the global and intercept, or
// rewrite, every request passing through it. The freeze only means anything if
// what the methods reach for cannot be swapped.
(() => {
    'use strict';

    const postMessagePromise = (data) => new Promise((resolve, reject) => {
        // crypto.randomUUID rather than Math.random().toString(36): these ids
        // correlate a reply to its request, and the page shares this message
        // channel.
        const id = crypto.randomUUID();
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

    const api = {
        version: "1.0.0",
        getAccount: async () => {
            return postMessagePromise({ type: 'TRUSTKEYS_GET_ACCOUNT' });
        },
        sign: async (message) => {
            return postMessagePromise({ type: 'TRUSTKEYS_SIGN', message });
        },
        // Self-signed binding of the active account's ML-KEM key to its identity
        // (audit M-1). Popup-free: the signed message is fixed and self-referential —
        // the page supplies nothing.
        getKeyAttestation: async () => {
            return postMessagePromise({ type: 'TRUSTKEYS_GET_KEY_ATTESTATION' });
        },
        // Silent chat-message signing (audit S1): auto-signs only `message`-domain
        // payloads, so the dApp can authenticate messages without a popup per send.
        signMessage: async (message) => {
            return postMessagePromise({ type: 'TRUSTKEYS_SIGN_MESSAGE', message });
        },
        verify: async (message, signature, publicKey) => {
            return postMessagePromise({ type: 'TRUSTKEYS_VERIFY', message, signature, publicKey });
        },
        encrypt: async (message, publicKey) => {
            return postMessagePromise({ type: 'TRUSTKEYS_ENCRYPT', message, publicKey });
        },
        decrypt: async (ciphertext) => {
            return postMessagePromise({ type: 'TRUSTKEYS_DECRYPT', data: ciphertext });
        },
        connect: async () => {
            return postMessagePromise({ type: 'TRUSTKEYS_CONNECT' });
        },
        isConnected: async () => {
            return postMessagePromise({ type: 'TRUSTKEYS_CHECK_CONNECTION' });
        },
        handshake: async () => {
            return postMessagePromise({ type: 'TRUSTKEYS_HANDSHAKE' });
        },
        generateSessionKey: async () => {
            return postMessagePromise({ type: 'TRUSTKEYS_GENERATE_SESSION_KEY' });
        },
        wrapSessionKey: async (sessionKey, publicKey) => {
            return postMessagePromise({ type: 'TRUSTKEYS_WRAP_SESSION_KEY', sessionKey, publicKey });
        },
        unwrapSessionKey: async (wrappedKey) => {
            return postMessagePromise({ type: 'TRUSTKEYS_UNWRAP_SESSION_KEY', wrappedKey });
        },
        unwrapManySessionKeys: async (wrappedKeys) => {
            return postMessagePromise({ type: 'TRUSTKEYS_UNWRAP_MANY_SESSION_KEYS', wrappedKeys });
        },
        // Batch PQC-envelope decrypt — one approval popup for the whole set (used
        // for encrypted entry titles, audit M-3). Per-item failures return null.
        decryptMany: async (items) => {
            return postMessagePromise({ type: 'TRUSTKEYS_DECRYPT_MANY', items });
        }
    };

    // Freeze the API object, and define the property as non-writable and
    // non-configurable so the page cannot simply reassign window.trustkeys to
    // an object of its own.
    Object.freeze(api);
    Object.defineProperty(window, 'trustkeys', {
        value: api,
        writable: false,
        configurable: false,
        enumerable: true,
    });
})();

